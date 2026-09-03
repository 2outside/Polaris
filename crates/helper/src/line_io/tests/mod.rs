use super::*;
use std::io::{BufReader, Cursor};

#[test]
fn reads_lines_and_trims_crlf() {
    let data = b"tok123\r\nping\nlast-no-newline";
    let mut r = BufReader::new(Cursor::new(&data[..]));
    assert_eq!(read_line_trimmed(&mut r).as_deref(), Some("tok123"));
    assert_eq!(read_line_trimmed(&mut r).as_deref(), Some("ping"));
    assert_eq!(
        read_line_trimmed(&mut r).as_deref(),
        Some("last-no-newline"),
        "末行无 \\n 仍应产出内容"
    );
    assert_eq!(read_line_trimmed(&mut r), None, "EOF → None");
}

#[test]
fn empty_line_is_some_empty_not_eof() {
    // 空行 vs EOF 必须可区分 —— linux handler 靠空串判「无参数」，EOF 判「连接断」。
    let mut r = BufReader::new(Cursor::new(&b"\n"[..]));
    assert_eq!(read_line_trimmed(&mut r).as_deref(), Some(""));
    assert_eq!(read_line_trimmed(&mut r), None);
}

#[test]
fn bounded_reader_stops_at_limit_plus_one_without_consuming_tail() {
    let mut r = BufReader::with_capacity(32, Cursor::new(b"12345TAIL\nnext\n"));
    assert!(matches!(
        read_line_trimmed_bounded(&mut r, 4),
        Err(BoundedLineError::TooLong { limit: 4 })
    ));
    assert_eq!(
        r.fill_buf().unwrap(),
        b"TAIL\nnext\n",
        "超限判定后不得继续消费攻击者尾部"
    );
}

#[test]
fn bounded_reader_accepts_exact_limit_and_trims_crlf() {
    let mut r = BufReader::new(Cursor::new(b"1234\nokay\r\n"));
    assert_eq!(
        read_line_trimmed_bounded(&mut r, 4).unwrap().as_deref(),
        Some("1234")
    );
    assert_eq!(
        read_line_trimmed_bounded(&mut r, 5).unwrap().as_deref(),
        Some("okay")
    );
}

#[test]
fn writes_line_with_newline() {
    let mut out: Vec<u8> = Vec::new();
    write_line(&mut out, "OK pong uid=0 v9").unwrap();
    write_line(&mut out, "OK stopped").unwrap();
    assert_eq!(&out[..], b"OK pong uid=0 v9\nOK stopped\n");
}

#[test]
fn write_line_propagates_io_error() {
    /// 恒失败 writer（模拟对端已断）。
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "gone"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    assert!(write_line(&mut Broken, "x").is_err());
}
