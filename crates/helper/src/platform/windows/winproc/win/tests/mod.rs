use super::*;

#[test]
fn wide_to_string_truncates_at_null() {
    let buf = [b'A'.into(), b'B'.into(), 0u16, b'C'.into()];
    assert_eq!(wide_to_string(&buf), "AB");
}
