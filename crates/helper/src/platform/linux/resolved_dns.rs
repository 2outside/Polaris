//! Linux `systemd-resolved` per-link DNS 接管。
//!
//! 该模块运行在 root helper 内，但能力被收敛到一个固定 TUN 接口与一个受控 DNS 哨兵；app 不能借此
//! 修改任意网卡或任意 DNS。写入是事务性的：任一步或读回自证失败都会 `revert` 已写状态。

use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(test)]
use polaris_helper_proto::linux_dns::CONTROLLED_DNS_IP;
use polaris_helper_proto::linux_dns::{
    takeover_request_allowed, ROUTE_ALL_DOMAIN, TUN_INTERFACE_NAME,
};

const RESOLVECTL_BIN: &str = "/usr/bin/resolvectl";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
// `resolvectl` 是启动主链上的短命令（一次接管含 8 次调用）。固定 20ms 轮询会给每次调用附加一格
// 尾延迟；指数退避让短命令 1ms 起被发现，而挂起命令最终仍回到原 20ms 上限，不改变 5s 硬超时。
const INITIAL_POLL_INTERVAL: Duration = Duration::from_millis(1);
const MAX_POLL_INTERVAL: Duration = Duration::from_millis(20);

fn next_poll_interval(current: Duration) -> Duration {
    current.saturating_mul(2).min(MAX_POLL_INTERVAL)
}

/// handler 依赖的最小能力面。
pub trait ResolvedDnsOps: Send + Sync {
    /// 接管并读回自证。
    fn takeover(&self, interface_name: &str, server_ip: &str) -> Result<(), String>;
    /// 撤销链路配置；接口已经消失视为无残留。
    fn revert(&self, interface_name: &str) -> Result<(), String>;
}

trait ResolvectlRunner: Send + Sync {
    fn link_exists(&self, interface_name: &str) -> bool;
    fn run(&self, args: &[&str]) -> Result<String, String>;
}

#[derive(Debug, Default)]
struct SystemResolvectlRunner;

impl ResolvectlRunner for SystemResolvectlRunner {
    fn link_exists(&self, interface_name: &str) -> bool {
        Path::new("/sys/class/net").join(interface_name).exists()
    }

    fn run(&self, args: &[&str]) -> Result<String, String> {
        run_resolvectl(RESOLVECTL_BIN, args)
    }
}

/// spawn `resolvectl` → 两条管道各起一个排空线程 → `try_wait` 轮询到硬超时。
///
/// # 排空线程必须起在轮询之前
///
/// 反过来写（先轮询等它退出、退出之后才去读管道）是死锁形态：子进程把管道写满之后，它的下一次
/// `write(2)` 会一直阻塞等父进程把管道读空，而父进程正在等它退出——两边互等，直到超时把子进程杀掉
/// 才解围。`crates/system-integration/src/exec.rs` 的 `StdCommandRunner` 早就把这条理由写在文档里；
/// 本函数此前恰恰是反的，只因为 `resolvectl dns|domain|default-route|revert` 每次只回一行、远小于管道
/// 容量（Linux 匿名管道默认 64 KiB）才没有击发。那是「输出量恰好够小」在兜底，不是形态正确：
/// `resolvectl status` 这类全量输出一旦进到这条腿上，5 秒硬超时就会从兜底变成常态。
///
/// # 为什么把可执行文件当参数传
///
/// 这个缺陷只在输出越过管道容量时才可观测，而 `resolvectl` 自己的输出量由系统状态决定、在测试里
/// 稳定不下来。参数化之后，回归测试可以拿一个必定写满管道的 shim 当被测输入
/// （见 `tests::resolvectl_runner_drains_output_larger_than_the_pipe_buffer`），而生产调用点仍然只有
/// 一个、仍然只喂 [`RESOLVECTL_BIN`]。错误文案里的 `resolvectl` 保持字面量，语义不随参数漂。
fn run_resolvectl(program: &str, args: &[&str]) -> Result<String, String> {
    let mut child = Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn resolvectl {}: {e}", args.join(" ")))?;

    // 先接管两条管道并起排空线程（见函数文档：顺序不可换）。
    let out_pipe = child.stdout.take();
    let err_pipe = child.stderr.take();
    let out_thread = thread::spawn(move || drain(out_pipe));
    let err_thread = thread::spawn(move || drain(err_pipe));

    let started = Instant::now();
    let mut poll_interval = INITIAL_POLL_INTERVAL;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // 子进程已退出 ⇒ 它自己那份管道写端已关。**但这只在子进程没有继承了写端的后代时
                // 等价于「读线程马上读到 EOF」**：只要还有一个孙子进程握着同一个写端，读线程就会
                // 一直阻塞在 `read_to_end` 上，无界 `join()` 会把整条调用挂死。`resolvectl` 不 fork，
                // 今天走不到那一格；但本函数的可执行文件已经是参数（回归测试喂的就是 `/bin/sh`），
                // 前提一旦不成立就不该由一次永久挂起来告诉我们。故 join 走有界收口。
                let stdout = join_within(out_thread, DRAIN_JOIN_BUDGET);
                let stderr = join_within(err_thread, DRAIN_JOIN_BUDGET);
                if status.success() {
                    return Ok(stdout.trim().to_owned());
                }
                let detail = if stderr.trim().is_empty() {
                    stdout.trim()
                } else {
                    stderr.trim()
                };
                return Err(format!(
                    "resolvectl {} exited {status}: {detail}",
                    args.join(" ")
                ));
            }
            Ok(None) if started.elapsed() < COMMAND_TIMEOUT => {
                thread::sleep(poll_interval);
                poll_interval = next_poll_interval(poll_interval);
            }
            Ok(None) => {
                // 硬超时：kill + 收割，再有界收掉两个读线程。**不能直接 return**：读线程仍握着
                // 管道读端，撒手不管就是每超时一次泄漏两个线程与两个 fd。这条路径原本连管道都不读，
                // 泄漏面是本批把「先读后等」搬进来时新引入的，属退化，必须在这里收掉。
                let _ = child.kill();
                let _ = child.wait();
                let _ = join_within(out_thread, DRAIN_JOIN_BUDGET);
                let _ = join_within(err_thread, DRAIN_JOIN_BUDGET);
                return Err(format!(
                    "resolvectl {} timed out after {}s",
                    args.join(" "),
                    COMMAND_TIMEOUT.as_secs()
                ));
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = join_within(out_thread, DRAIN_JOIN_BUDGET);
                let _ = join_within(err_thread, DRAIN_JOIN_BUDGET);
                return Err(format!("wait resolvectl {}: {e}", args.join(" ")));
            }
        }
    }
}

/// 有界 join：预算内线程自己结束就取它的内容，超过预算就放弃 join 并返回空串。
///
/// # 为什么不是直接 `join()`
///
/// 无界 `join()` 的正确性前提是「子进程退出 ⇒ 管道写端全部关闭 ⇒ 读线程立刻 EOF」。这个前提只在
/// 子进程**没有继承了写端的后代**时成立：只要还有一个孙子进程握着同一个写端，读线程就一直阻塞在
/// `read_to_end` 上，`join()` 跟着永久挂住——而挂住的是 root helper 的一条请求处理路径。
///
/// # 放弃 join 之后会怎样（射程要写准）
///
/// 放弃只保证**调用方不被挂死**，不回收那个线程：它仍然持有读端，直到管道对端全部关闭才结束。
/// 换句话说，这是把「永久挂起」换成「有界的一次线程 + fd 泄漏」，不是把泄漏消掉。真正消掉它需要
/// 可中断的读（`O_NONBLOCK` + poll），那是另一个量级的改动，本批不做。
const DRAIN_JOIN_BUDGET: Duration = Duration::from_secs(1);

fn join_within(handle: thread::JoinHandle<String>, budget: Duration) -> String {
    let deadline = Instant::now() + budget;
    while !handle.is_finished() {
        if Instant::now() >= deadline {
            return String::new();
        }
        thread::sleep(INITIAL_POLL_INTERVAL);
    }
    handle.join().unwrap_or_default()
}

/// 把一条管道读到 EOF；读不动就当空串。形态与 `system-integration::exec::drain` 一致。
///
/// 与旧实现（`read_to_string`）的唯一可观测差别：子进程输出**不是**合法 UTF-8 时，旧写法整段丢弃
/// （`detail` 变成空串），本写法走 lossy 替换留下可读文本。四条返回路径的错误文案模板逐字未变，
/// 变的只是 `detail` 这个填空位在这一种输入下的取值——方向是多留诊断，不是少留。
/// `LC_ALL=C` 下 `resolvectl` 的输出本就是 ASCII，生产路径上取不到这个差别。
fn drain(pipe: Option<impl Read>) -> String {
    let Some(mut pipe) = pipe else {
        return String::new();
    };
    let mut buf = Vec::new();
    if pipe.read_to_end(&mut buf).is_err() {
        return String::new();
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// 生产实现。
#[derive(Debug, Default)]
pub struct ResolvectlDnsOps {
    runner: SystemResolvectlRunner,
}

impl ResolvectlDnsOps {
    /// 构造生产实现。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl ResolvedDnsOps for ResolvectlDnsOps {
    fn takeover(&self, interface_name: &str, server_ip: &str) -> Result<(), String> {
        takeover_with(&self.runner, interface_name, server_ip)
    }

    fn revert(&self, interface_name: &str) -> Result<(), String> {
        revert_with(&self.runner, interface_name)
    }
}

fn takeover_with(
    runner: &dyn ResolvectlRunner,
    interface_name: &str,
    server_ip: &str,
) -> Result<(), String> {
    if !takeover_request_allowed(interface_name, server_ip) {
        return Err("request denied by Polaris resolved whitelist".to_owned());
    }
    if !runner.link_exists(interface_name) {
        return Err(format!("managed TUN interface {interface_name} is missing"));
    }

    let mutations: [&[&str]; 5] = [
        &["dnssec", interface_name, "no"],
        &["dnsovertls", interface_name, "no"],
        &["dns", interface_name, server_ip],
        &["domain", interface_name, ROUTE_ALL_DOMAIN],
        &["default-route", interface_name, "yes"],
    ];
    for args in mutations {
        if let Err(error) = runner.run(args) {
            return Err(rollback_error(runner, interface_name, error));
        }
    }

    let attestation = attest(runner, interface_name, server_ip);
    if let Err(error) = attestation {
        return Err(rollback_error(runner, interface_name, error));
    }
    Ok(())
}

fn attest(
    runner: &dyn ResolvectlRunner,
    interface_name: &str,
    server_ip: &str,
) -> Result<(), String> {
    let dns = runner.run(&["dns", interface_name])?;
    if !dns.split_whitespace().any(|token| token == server_ip) {
        return Err(format!("resolved read-back missing DNS {server_ip}: {dns}"));
    }
    let domains = runner.run(&["domain", interface_name])?;
    if !domains
        .split_whitespace()
        .any(|token| token == ROUTE_ALL_DOMAIN)
    {
        return Err(format!(
            "resolved read-back missing route-only domain {ROUTE_ALL_DOMAIN}: {domains}"
        ));
    }
    let default_route = runner.run(&["default-route", interface_name])?;
    if !default_route
        .split_whitespace()
        .any(|token| token.eq_ignore_ascii_case("yes"))
    {
        return Err(format!(
            "resolved read-back did not confirm default-route=yes: {default_route}"
        ));
    }
    Ok(())
}

fn rollback_error(runner: &dyn ResolvectlRunner, interface_name: &str, cause: String) -> String {
    match runner.run(&["revert", interface_name]) {
        Ok(_) => format!("{cause}; partial resolved state reverted"),
        Err(rollback) => format!("{cause}; rollback failed: {rollback}"),
    }
}

fn revert_with(runner: &dyn ResolvectlRunner, interface_name: &str) -> Result<(), String> {
    if interface_name != TUN_INTERFACE_NAME {
        return Err("request denied by Polaris resolved whitelist".to_owned());
    }
    if !runner.link_exists(interface_name) {
        return Ok(());
    }
    runner.run(&["revert", interface_name]).map(|_| ())
}

#[cfg(test)]
mod tests;
