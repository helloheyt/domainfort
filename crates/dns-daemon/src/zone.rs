//! The zone image dnsd answers from, and the one thread that fetches it.
//!
//! # The image (docs/54 §4.4)
//!
//! A [`ZoneImage`] (crates/dns-zone: typed, immutable, validated by
//! `ZoneImage::new` — and again by the channel's assembly on dnsd's side,
//! A-152) with the time dird last **confirmed** its SERIAL. A query reads
//! both and asks dns-zone whether the image is current
//! (`ZoneState::from_confirmation`): past `zone_image_max_age` without a
//! confirmation — or with no image at all — every query is answered
//! SERVFAIL (fail closed: a deleted host's record is not served for ever
//! while dird is down — docs/54 §4.4; Q-616 item 6).
//!
//! The confirmation time is read **before** the fetch is sent (the older of
//! the two possible readings), so an image is never treated as fresher than
//! dird's answer could be.
//!
//! # One writer, by construction (RFC 2136 §3.7)
//!
//! The slot is split into a [`ZoneView`] (cloned into every listener: read
//! only) and a [`ZoneWriter`] (not `Clone`), which is moved into the zone
//! thread and nowhere else. So the image is replaced only as a whole
//! (`Arc` swap under the lock — "a query never sees a partial state",
//! docs/54 §4.4; RFC 2136 §3.7) and only by the one thread that also asks
//! dird — two fetches can never race to install an older image over a newer
//! one, because there is only one fetcher. The forwarding thread asks the
//! zone thread for a fetch (crate::forward) instead of fetching itself.
//!
//! # The zone thread
//!
//! It owns its own [`DnsClient`] — its own connection to dird, verified on
//! every connection by uid and by the zone dird names in its `Pong`
//! (`ExpectedDird`, docs/54 §4.6; C12) — and:
//!
//! 1. **start** (docs/54 §4.8, as amended by A-152 / Q-922): `FetchZoneImage
//!    { have: None }` on a fresh connection — whose first exchange is the
//!    verifying `Ping` → `Pong` — and reports the outcome; any failure ⇒ the
//!    daemon does not start (dird down at start ⇒ dnsd does not come up);
//! 2. **refresh** every [`crate::limits::REFRESH_INTERVAL`], and at once when
//!    the forwarding thread asks (dird's reply named another SERIAL —
//!    docs/54 §4.4 (a)): `FetchZoneImage { have: Some(current) }` →
//!    `Unchanged` confirms the image, a new image replaces it whole, a
//!    failure leaves it ageing toward the bound;
//! 3. ends when every sender of its request channel is gone (stop).
//!
//! The thread blocks on dird (the client is synchronous, docs/50 §3.6):
//! that is why it is a thread of its own and not a task of the listeners'
//! runtime (RFC 1035 §4.2.2: "The server should not block other activities
//! waiting for TCP data").
//!
//! Spec: docs/54 §4.4, §4.6, §4.8; A-152 (Q-922); RFC 2136 §3.6, §3.7;
//! docs/questions/Q-616 item 6, Q-921 item 6.

use crate::clock::Clock;
use crate::log::{note, Note, ZONE_REFRESH_FAILED};
use core::time::Duration;
use dns_zone::{ZoneImage, ZoneState};
use ipc_dns::{Connector, DnsClient, ImageFetch, Serial, Unserved};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, RwLock};
use std::thread::JoinHandle;
use tokio::sync::oneshot;

/// The image and the time dird last confirmed its SERIAL.
/// Spec: docs/54 §4.4.
#[derive(Debug)]
pub(crate) struct Held {
    image: Arc<ZoneImage>,
    confirmed_at: u64,
}

impl Held {
    /// The image's state at `now`, under the staleness bound `max_age`
    /// (seconds, dnsd's monotonic clock).
    /// Spec: docs/54 §4.4; crates/dns-zone `ZoneState::from_confirmation`.
    pub(crate) fn state(&self, now: u64, max_age: u64) -> ZoneState<'_> {
        ZoneState::from_confirmation(&self.image, self.confirmed_at, now, max_age)
    }
}

/// The slot both halves share.
#[derive(Debug, Default)]
struct Slot {
    held: RwLock<Option<Arc<Held>>>,
}

/// The read half: every listener's view of the current image.
/// Spec: module documentation.
#[derive(Debug, Clone)]
pub(crate) struct ZoneView {
    slot: Arc<Slot>,
}

impl ZoneView {
    /// The image and its confirmation time, if any. A poisoned lock reads as
    /// no image (fail closed — SERVFAIL).
    pub(crate) fn current(&self) -> Option<Arc<Held>> {
        self.slot.held.read().ok().and_then(|held| held.clone())
    }

    /// The SERIAL of the image served, if any.
    pub(crate) fn serial(&self) -> Option<u32> {
        self.current().map(|held| held.image.serial())
    }
}

/// The write half: only the zone thread has it (not `Clone`).
/// Spec: module documentation.
#[derive(Debug)]
pub(crate) struct ZoneWriter {
    slot: Arc<Slot>,
}

impl ZoneWriter {
    /// Replace the image as a whole, confirmed at `at`.
    /// Spec: docs/54 §4.4 ("atomic replacement"); RFC 2136 §3.7.
    fn install(&self, image: ZoneImage, at: u64) {
        let held = Arc::new(Held {
            image: Arc::new(image),
            confirmed_at: at,
        });
        if let Ok(mut slot) = self.slot.held.write() {
            *slot = Some(held);
        }
    }

    /// dird confirmed that the image served (SERIAL `serial`) is current, at
    /// `at`. Only that image is confirmed: another SERIAL changes nothing.
    /// Spec: docs/54 §4.4.
    fn confirm(&self, serial: Serial, at: u64) {
        if let Ok(mut slot) = self.slot.held.write() {
            let renewed = match slot.as_ref() {
                Some(held) if held.image.serial() == serial.get() => Some(Arc::new(Held {
                    image: Arc::clone(&held.image),
                    confirmed_at: at,
                })),
                _ => None,
            };
            if let Some(renewed) = renewed {
                *slot = Some(renewed);
            }
        }
    }

    /// The SERIAL of the image served, if any, as the channel spells it.
    fn have(&self) -> Option<Serial> {
        self.slot
            .held
            .read()
            .ok()
            .and_then(|held| held.as_ref().map(|held| held.image.serial()))
            .and_then(Serial::new)
    }
}

/// An empty slot: the read half for the listeners, the write half for the
/// zone thread. Spec: module documentation.
pub(crate) fn slot() -> (ZoneView, ZoneWriter) {
    let slot = Arc::new(Slot::default());
    (
        ZoneView {
            slot: Arc::clone(&slot),
        },
        ZoneWriter { slot },
    )
}

/// A request to the zone thread: fetch now, then signal `done`.
/// Spec: docs/54 §4.4 (a).
#[derive(Debug)]
pub(crate) struct RefreshNow {
    pub(crate) done: SyncSender<()>,
}

/// Everything the zone thread runs with.
pub(crate) struct ZoneThread<C: Connector> {
    pub(crate) client: DnsClient<C>,
    pub(crate) writer: ZoneWriter,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) interval: Duration,
    pub(crate) requests: Receiver<RefreshNow>,
    /// The start outcome: the first image's SERIAL, or why dird did not
    /// serve it.
    pub(crate) started: oneshot::Sender<Result<u32, Unserved>>,
}

/// Spawn the zone thread (module documentation).
///
/// # Errors
/// The thread could not be spawned.
///
/// Spec: docs/54 §4.4, §4.8.
pub(crate) fn spawn<C>(thread: ZoneThread<C>) -> std::io::Result<JoinHandle<()>>
where
    C: Connector + Send + 'static,
    C::Connection: Send,
{
    std::thread::Builder::new()
        .name("dnsd-zone".to_owned())
        .spawn(move || run(thread))
}

/// The zone thread's body. Spec: module documentation.
fn run<C: Connector>(thread: ZoneThread<C>) {
    let ZoneThread {
        mut client,
        writer,
        clock,
        interval,
        requests,
        started,
    } = thread;
    // 1. Start: the whole image, on a connection verified first.
    let at = clock.now_secs();
    match client.fetch_zone_image(None) {
        Ok(ImageFetch::Image(image)) => {
            let serial = image.serial();
            writer.install(*image, at);
            if started.send(Ok(serial)).is_err() {
                return;
            }
        }
        // `have: None` is never answered `Unchanged` by a conforming client
        // (crates/ipc-dns refuses it as an unexpected reply); fail closed.
        Ok(ImageFetch::Unchanged(_)) => {
            let _ = started.send(Err(Unserved::UnexpectedReply));
            return;
        }
        Err(unserved) => {
            let _ = started.send(Err(unserved));
            return;
        }
    }
    // 2. Refresh until stopped.
    loop {
        let done = match requests.recv_timeout(interval) {
            Ok(RefreshNow { done }) => Some(done),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => return,
        };
        refresh(&mut client, &writer, &*clock);
        if let Some(done) = done {
            let _ = done.send(());
        }
    }
}

/// One SERIAL check: confirm, replace, or let the image age.
/// Spec: docs/54 §4.4; crates/ipc-dns `DnsClient::fetch_zone_image`.
fn refresh<C: Connector>(client: &mut DnsClient<C>, writer: &ZoneWriter, clock: &dyn Clock) {
    let have = writer.have();
    let at = clock.now_secs();
    match client.fetch_zone_image(have) {
        Ok(ImageFetch::Unchanged(serial)) => writer.confirm(serial, at),
        Ok(ImageFetch::Image(image)) => {
            let serial = image.serial();
            writer.install(*image, at);
            note(Note::ZoneImageReplaced, Some(u64::from(serial)));
        }
        Err(_) => ZONE_REFRESH_FAILED.hit(),
    }
}

/// TESTS ONLY: a view of a slot holding `image`, confirmed at `at` (the
/// in-crate listener tests; the writer is dropped, as no thread runs).
#[cfg(test)]
pub(crate) fn current_for_test(image: ZoneImage, at: u64) -> ZoneView {
    let (view, writer) = slot();
    writer.install(image, at);
    view
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use dns_zone::{HostRecordParts, KpasswdService, SoaParameters, ZoneImageParts};
    use ipc_dns::Name;
    use std::net::Ipv4Addr;

    /// The RFC 2782 "Fictional example" zone (SOA timers and the `server`
    /// host 172.30.79.10), with SERIAL `serial` (hand-made).
    pub(crate) fn image(serial: u32) -> ZoneImage {
        let host = |label: &str, address: [u8; 4]| HostRecordParts {
            label: label.as_bytes().to_vec(),
            addresses: vec![Ipv4Addr::from(address)],
            ttl: 3600,
        };
        ZoneImage::new(ZoneImageParts {
            apex: Name::from_dotted("example.com").expect("name"),
            serial,
            soa: SoaParameters {
                rname: Name::from_dotted("root.example.com").expect("name"),
                refresh: 3600,
                retry: 3600,
                expire: 604_800,
                minimum: 86_400,
            },
            infrastructure_ttl: 3600,
            dc: host("server", [172, 30, 79, 10]),
            hosts: vec![host("old-slow-box", [172, 30, 79, 11])],
            kpasswd: KpasswdService::Absent,
        })
        .expect("valid image")
    }

    fn current(view: &ZoneView, now: u64, max_age: u64) -> bool {
        view.current()
            .is_some_and(|held| matches!(held.state(now, max_age), ZoneState::Current(_)))
    }

    /// docs/54 §4.4: no image ⇒ unavailable; an image is current until
    /// `max_age` past its confirmation, then unavailable; a confirmation of
    /// the served SERIAL renews it, one of another SERIAL does not; a
    /// replacement is whole. crates/dns-zone: a time before the
    /// confirmation is stale (fail closed).
    #[test]
    fn the_image_is_current_only_within_the_bound() {
        let (view, writer) = slot();
        assert!(view.current().is_none());
        assert_eq!(writer.have(), None);
        writer.install(image(7), 100);
        assert_eq!(view.serial(), Some(7));
        assert!(current(&view, 100, 60));
        assert!(current(&view, 160, 60));
        assert!(!current(&view, 161, 60));
        assert!(!current(&view, 99, 60), "a clock before the confirmation");
        writer.confirm(Serial::new(8).expect("serial"), 200);
        assert!(!current(&view, 200, 60), "another SERIAL confirms nothing");
        writer.confirm(Serial::new(7).expect("serial"), 200);
        assert!(current(&view, 260, 60));
        writer.install(image(9), 300);
        assert_eq!(view.serial(), Some(9));
        assert_eq!(writer.have(), Serial::new(9));
    }
}
