#![no_main]
use libfuzzer_sys::fuzz_target;
use sigil::RevocationList;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = RevocationList::from_json(s);
    }
});
