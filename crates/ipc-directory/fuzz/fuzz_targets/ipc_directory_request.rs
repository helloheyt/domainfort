#![no_main]
//! Fuzz target for the directory-view channel's server-side request
//! decoding: `ipc::decode_body` (bound, magic, exact version, closed kind
//! table, fields, no trailing octet), then `Request::from_wire` (every
//! `PrincipalName` through krb-proto's strict DER, realms as KerberosStrings,
//! SIDs through dtyp, group sets strictly ascending).
//!
//! docs/CLEAN-ROOM.md / docs/50 §9 (R50-19): arbitrary bytes → decoder; never a
//! panic, bounded allocation. Whatever decodes must re-encode to exactly the
//! input (docs/50 §3.3: "a single encoding per value"), and a rejection maps
//! to the refusal table (a shared `Refused`, or a close without a reply).
//!
//! Spec: docs/50 §3.3, §3.4, §9; R50-4; A-59.

use ipc::{decode_body, encode_frame, Direction};
use ipc_directory::typed::Request;
use ipc_directory::wire::DirectoryRequest;
use ipc_directory::DIRECTORY_CHANNEL;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    match decode_body::<DirectoryRequest>(DIRECTORY_CHANNEL, Direction::Request, data) {
        Ok(wire) => {
            let again = encode_frame(DIRECTORY_CHANNEL, Direction::Request, &wire)
                .expect("a decoded request re-encodes");
            assert_eq!(again.body(), data, "canonical wire round trip");
            if let Ok(request) = Request::from_wire(&wire) {
                let typed = request.to_wire().expect("a typed request re-encodes");
                assert_eq!(typed, wire, "canonical typed round trip");
            }
        }
        Err(error) => {
            // Either a shared refusal or a close; never anything else.
            let _ = error.refusal();
        }
    }
});
