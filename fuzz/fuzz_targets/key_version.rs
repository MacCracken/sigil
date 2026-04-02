#![no_main]
use libfuzzer_sys::fuzz_target;
use sigil::trust::KeyVersion;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<KeyVersion>(s);
    }
});
