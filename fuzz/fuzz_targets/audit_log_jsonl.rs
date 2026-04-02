#![no_main]
use libfuzzer_sys::fuzz_target;
use sigil::AuditLog;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = AuditLog::from_json_lines(s);
    }
});
