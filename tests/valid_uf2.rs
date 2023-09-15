use std::collections::HashMap;
use std::fs::read;
use std::process::Command;

#[test]
fn test() {
    let uf2 = include_bytes!("test.uf2");
    let output = Command::new("python3")
        .current_dir("official/utils/")
        .arg("uf2conv.py")
        .arg("../../tests/test.uf2")
        .arg("--output")
        .arg("../../tests/test.bin")
        .output()
        .unwrap();
    assert_eq!(
        concat!(
            "--- UF2 File Header Info ---\n",
            "Family ID is RP2040, hex value is 0xe48bff56\n",
            "Target Address is 0x10000000\n",
            "All block flag values consistent, 0x2000\n",
            "----------------------------\n",
            "Converted to bin, output size: 16640, start address: 0x10000000\n",
            "Wrote 16640 bytes to ../../tests/test.bin\n"
        ),
        String::from_utf8(output.stdout).unwrap()
    );
    let (converted, family_to_target) = uf2_decode::convert_from_uf2(uf2).unwrap();
    assert_eq!(
        family_to_target,
        HashMap::from([(0xe48b_ff56, 0x1000_0000)])
    );
    assert_eq!(converted, read("tests/test.bin").unwrap());
}
