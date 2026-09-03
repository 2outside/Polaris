//! 测试专用探针二进制：把 spawner 的真实接线变成**可断言的 stdout**。不进任何发布产物。
//!
//! **为什么需要它**：`spawner` 的真实 spawn 门原先拿 `/bin/echo`、`/bin/sleep`、临时 shell 脚本
//! 当「核」——这三样在 Windows 上都不存在，于是那几条门要么 `eprintln!("[skip]") + return`
//! （跳过型门 = 没有门），要么直接 `panic!`（Windows CI 恒红，实际发生过：release gate 首次跑满
//! 3-OS 矩阵即挂在 `tokio_spawner_passes_run_subcommand_to_child`）。换成本 crate 自己的 bin
//! 目标后，三平台跑的是同一条真实 spawn 路径，门不再有平台盲区。
//!
//! **模式由 argv 选**：`SpawnRequest::argv()` 恒为 `run -c <config>`，没有别的旋钮可拧——
//! `<config>` 那一格就是模式选择器（探针从不真的打开这个路径，只按字面量分派）。
//!
//! | argv 含 | 行为 | 服务于 |
//! |---|---|---|
//! | `--pwd` | 打印当前工作目录 | `working_dir` 接线 |
//! | `--sleep` | 常驻 30s | pid 可读 + 进程可被 kill |
//! | `--flood-stderr[:<字节数>]` | 往 stderr 灌指定字节（默认 1 MiB）后退出 0 | `StdioPolicy` 真的把管道排空了 |
//! | 其余 | 把 `argv[1..]` 空格连接打回 stdout | argv 完整传递（含 `run` 子命令） |
//!
//! `--flood-stderr` 是 stdio 收口那道进程级门的被测对象：字节数远大于任何平台的管道容量
//! （Linux 64 KiB / macOS 初始 16 KiB / Windows 未核实），**没人读就一定卡在 `write(2)` 上**。
//! 它只写自己的 fd 2，不开端口、不碰网络、不认识 sing-box。

/// `--flood-stderr` 不带 `:<字节数>` 时灌多少字节。1 MiB ≫ 各平台管道容量。
const DEFAULT_FLOOD_BYTES: usize = 1024 * 1024;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--pwd") {
        println!(
            "{}",
            std::env::current_dir().expect("读当前工作目录").display()
        );
    } else if args.iter().any(|a| a == "--sleep") {
        std::thread::sleep(std::time::Duration::from_secs(30));
    } else if let Some(spec) = args.iter().find(|a| a.starts_with("--flood-stderr")) {
        flood_stderr(
            spec.split_once(':')
                .and_then(|(_, n)| n.parse().ok())
                .unwrap_or(DEFAULT_FLOOD_BYTES),
        );
    } else {
        println!("{}", args.join(" "));
    }
}

/// 往 stderr 灌 `total` 字节（逐行 1 KiB，与真核「每连接若干行」的产出形态同构）后正常退出。
///
/// 写失败即停：管道读端被关（`Discard` 之外的对照腿）时这里拿到的是 EPIPE，不是该报错的场景。
fn flood_stderr(total: usize) {
    use std::io::Write;
    let mut line = vec![b'x'; 1023];
    line.push(b'\n');
    let err = std::io::stderr();
    let mut sink = err.lock();
    let mut sent = 0usize;
    while sent < total {
        if sink.write_all(&line).is_err() {
            return;
        }
        sent += line.len();
    }
    let _ = sink.flush();
}
