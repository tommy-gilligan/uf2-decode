#![no_main]

use libfuzzer_sys::fuzz_target;
use uf2_decode::convert_from_uf2;

fuzz_target!(|data: &[u8]| {
    let _ = convert_from_uf2(data);
});
