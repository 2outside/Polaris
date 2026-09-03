use crate::test_support::{crate_code, module_files};

/// 被守的调用点标记（带 `self.` 前缀 ⇒ 不会撞上各自的 `fn` 定义行）。
const INVALIDATE: &str = "self.invalidate_unlock_cache(";

/// 出口 IP 腿的**全部合法形态**（同一物理事实的下游，任一出现即算配对）。
///
/// 为什么是三个而不是一个：「出口换了一次」的下游动作**本来就分岔**——
/// - [`REFRESH`]：出口有效、值待测 ⇒ 排一次真探测（起核 / 停核 / 热切 / TS 隧道就绪 / 出口恢复）；
/// - [`MARK_BLOCKED`]：出口**已知无效** ⇒ 不探测、直落终态（R2 `none→blocked`）。此时排探测是错的：
///   必然打空转 20s 重试预算再吐 null，用户看到「一直在检测」而不是「出口无效」；
/// - [`RECOVERY`]：出口恢复 ⇒ 先热重设 exit_node + 重申路由**再**探（顺序不可换，见
///   `ts_exit_recover_once`）。探测调用在异步腿内部（`me.` 前缀，不带 `self.`），故必须把
///   恢复腿本身登记成一条合法形态，否则守卫会把它误判成「有失效没重探」。
///
/// **放宽了吗？没有**：守卫的射程仍是「每个失效点旁必须有一个被点名的出口 IP 腿」+「总数写死」。
/// 新增第四种形态同样要改这张表 —— 那正是要逼出的那次显式裁定。
///
/// [`REFRESH`]: self::REFRESH
/// [`MARK_BLOCKED`]: self::MARK_BLOCKED
/// [`RECOVERY`]: self::RECOVERY
const REFRESH: &str = "self.schedule_exit_ip_refresh(";
const MARK_BLOCKED: &str = "self.mark_exit_blocked(";
const RECOVERY: &str = "self.spawn_ts_exit_recovery(";
const EXIT_IP_LEGS: &[&str] = &[REFRESH, MARK_BLOCKED, RECOVERY];

/// 已知触发点数（起核就绪 / 停核 / 用户热切成功 / **自动故障热切自证成功** / **自动故障
/// 双失败后的 selector 对账成功** / TS 隧道就绪 / **R2 出口无效 none→blocked** /
/// **R2 出口恢复 blocked→none**）。**写死是刻意的**：数目变了
/// 就说明有人动了触发表，该让他停下来显式裁定新触发点要不要重探出口 IP，而不是让守卫自适应地放行。
///
/// 第四点（TS 隧道就绪，`apply_ts_status_frame`）是 2026-07-21 补的：§10.1 的 上游 触发表本就含它，
/// 而 Polaris 侧只接了「广播半边」（emit_tailscale_status），既不失效解锁缓存也不重探出口 IP ——
/// 守卫当时**对它天然失明**（它压根不在扫描命中的三个点里）。补线后数目从 3 变 4，守卫方能看见。
///
/// 第五点（自动故障热切）只在 selector 回读和配置 CAS 均自证后计一次；未自证而恢复旧 selector
/// 的瞬态最终出口没有变化，刻意不失效缓存、不重探。新增的双失败恢复腿只有在 selector 回读
/// 自证后才提交 R，此时出口从不确定态收敛到 D，必须同步失效/重探。其后两点
///（`reconcile_ts_exit_block` 的两条跨态腿）是 R2 补的：出口从有效变无效 / 从无效恢复，与前述点是
/// **同一个物理事实**（当前出口换了），
/// 只是下游动作分岔成「落终态」与「先修再探」。
const KNOWN_TRIGGER_SITES: usize = 8;

/// 出口 IP 腿的**调用点**总数 = 触发点数 + 1。
///
/// 多出的那一条是 `ts_exit_recover_once` 里的 `schedule_exit_ip_refresh` —— 它不是独立触发点，
/// 而是**恢复腿自己的收尾**（`reapply → reassert → refresh` 三步的第三步，见该方法文档）。
/// 触发侧记的是 `spawn_ts_exit_recovery`，真探测被推迟到那条异步腿里执行。
///
/// **为什么不把它并进触发点数**：那会让「有失效没配腿」的判据被稀释 —— 两个数各自写死、各自解释，
/// 谁变了都要停下来说清楚，正是本守卫要的效果。
const KNOWN_EXIT_IP_LEG_SITES: usize = KNOWN_TRIGGER_SITES + 1;

/// 生产区源码（**净化面**：行注释、块注释、字符串字面量整段抹空，换行与行位保留），
/// **逐文件**返回，不拼接。
///
/// 注释必须剥，否则守卫假红：文档注释里 `[`invalidate_unlock_cache`]` 这类链接遍布
///（不剥 ⇒ 注释被当调用点）。
///
/// **只剥整行注释不够**（复审 2026-08-31 tests12域-判据）：行尾注释与字符串字面量里的
/// 锚点文本会给肯定型断言充数。输入对差 —— 旧判据（只剥整行 `//`）放行、新判据（净化面）
/// 拦截的样本：「删掉一条真腿 + 在配对窗口内某个**代码行**加一条提到该腿的行尾注释」——
/// 配对断言与写死的腿总数 9 同时被喂饱，两条门一起假绿；净化面下该注释被抹空，两条门
/// 都转红。现状（9 条真腿、无行尾注释充数）旧新同判。净化实现复用
/// [`polaris_source_probe::mask_comments_and_strings`]（字节偏移与行号都不变）。
///
/// **不再按 `mod tests` 截断**：测试实体已整体外移到 `runtime/proxy/tests/`，`module_files` 已排除
/// `tests/` ⇒ 「测试代码自己就能满足配对断言」的自指假绿在结构上不再可能。
///
/// **B0 换锚**：`proxy.rs` 内的生产职责会分批搬进 `proxy/<域>.rs`（子模块），取材面必须从单文件
/// `crate_source` 换成递归目录 `module_files`，否则搬走的方法会让 `find` 直接落空（响红，见
/// `feedback_rewritten_criterion_can_be_weaker`）。**逐文件返回而不是拼成一块**是本条唯一需要改
/// 判据形状的地方：下面 `WINDOW` 配对若对拼接后的单一 `Vec<String>` 做窗口扫描，触发点与重探腿就
/// 可能一个在文件 A 末尾、一个在文件 B 开头也能配对成功——「有失效没重探」的真缺陷会被邻居文件
/// 顶替作证（R2）。改成 `Vec<(路径, 该文件的行)>` 后，配对只在**同一个文件内**的窗口里找，
/// 跨文件永远配不上。
fn production_files() -> Vec<(String, Vec<String>)> {
    module_files("runtime/proxy")
        .into_iter()
        .map(|(path, source)| {
            let masked = polaris_source_probe::mask_comments_and_strings(&source);
            (path, masked.lines().map(str::to_string).collect())
        })
        .collect()
}

/// [`production_files`] 摊平成单一序列，供不依赖「同文件」这条边界的断言（总数 / 存在性 / 长度）
/// 使用——这些断言本就不看行与行的相邻关系，摊平不引入 R2 那种跨文件假绿。
fn production_lines() -> Vec<String> {
    production_files()
        .into_iter()
        .flat_map(|(_, lines)| lines)
        .collect()
}

/// 每个 `invalidate_unlock_cache` 调用点后 `WINDOW` 行内必须出现 `schedule_exit_ip_refresh`。
/// 窗口留 6 行是为容纳两者之间那段解释性注释（注释已被剥成空行，仍占行位）。
const WINDOW: usize = 6;

#[test]
fn every_unlock_invalidation_site_also_refreshes_exit_ip() {
    let files = production_files();
    // 逐文件找触发点索引，先求总数——与原判据同序：数目先钉，配对再查。
    let per_file_sites: Vec<(&str, &Vec<String>, Vec<usize>)> = files
        .iter()
        .map(|(path, lines)| {
            let sites: Vec<usize> = lines
                .iter()
                .enumerate()
                .filter(|(_, l)| l.contains(INVALIDATE))
                .map(|(i, _)| i)
                .collect();
            (path.as_str(), lines, sites)
        })
        .collect();
    let total_sites: usize = per_file_sites.iter().map(|(_, _, sites)| sites.len()).sum();
    assert_eq!(
        total_sites, KNOWN_TRIGGER_SITES,
        "触发点数量变了（{total_sites} 个）：新增/删除「出口换了一次」的判定点时，必须同时裁定出口 IP 重探腿"
    );
    for (path, lines, sites) in per_file_sites {
        for i in sites {
            // 窗口不越过 `lines`（本文件）的尾部 ⇒ 配对天然锁在同一个文件内，不会被下一个文件
            // 开头的腿顶替作证。
            let paired = lines[i + 1..(i + 1 + WINDOW).min(lines.len())]
                .iter()
                .any(|l| EXIT_IP_LEGS.iter().any(|leg| l.contains(leg)));
            assert!(
                paired,
                "`{path}` 第 {} 行的 invalidate_unlock_cache 后 {WINDOW} 行内没有任何出口 IP 腿\
                     （重探 / 落无效终态 / 恢复腿）⇒ 该触发点的出口 IP/延迟不会自动刷新，\
                     退回「必须手点网络检测」的真机缺陷",
                i + 1
            );
        }
    }
}

/// 🔵 **接线守卫**：`mark_exit_blocked` 必须**委托**给 `commands::misc` 的权威缓存写入腿，
/// 而不是就地 broadcast 一帧了事。
///
/// # 这条补的是什么洞
///
/// 旧实现只 `broadcast(EVENT_IP_INFO_UPDATED, …)`。事件只喂**订阅方**（状态栏）；`ipinfo:get(peek)`
/// 型消费方（托盘浮层每次弹出即 peek、主窗窗口重建水合）**不订阅**、只读 `IPINFO_CACHE` ⇒ 出口被
/// 直判无效之后，那两处继续吐上一次探到的代理出口 IP。同屏两处对「我现在从哪出去」互相矛盾，且错的
/// 那个是「用一个已知无效的旧出口冒充当前出口」。
///
/// 行为测试够不着：本方法在 `AppHandleProxyErrorEmitter` 上，要真 `AppHandle`（本仓未引 `tauri::test`）。
///
/// # 为什么不能对整个文件 `contains`
///
/// 委托调用 `crate::commands::misc::mark_ipinfo_proxy_blocked(` 只要在 `proxy.rs` **任意位置**出现
/// 一次就能满足文件级 `contains`，与它是否还挂在 `mark_exit_blocked` 身上无关——把这句调用挪进别的
/// 方法，文件级断言照样绿。「② 删掉委托调用 → 转红」这条牙只在「剥注释后全文件仅此一处」的**偶然**
/// 条件下成立，靠不住。故先按 `impl ProxyErrorEmitter for AppHandleProxyErrorEmitter` 切出这个
/// impl 块，只在块内找这句委托——挪出这个 impl 块（哪怕挪到同文件别处）也一样转红。
///
/// # 为什么不能直接 `impl_method_body("    fn mark_exit_blocked(")`
///
/// `proxy.rs` 里 `fn mark_exit_blocked` 有三个定义：trait 声明（`;` 结尾、无函数体）、
/// `AppHandleProxyErrorEmitter` 上的真委托实现、`ProxyRuntime` 上的转发。`impl_method_body` 的
/// 唯一性断言 `find` 命中 3 次会当场 panic——必须先按 impl 块切一层，把「切哪一个」的判定挪到
/// impl 块粒度（此处唯一），而不是同名方法粒度（此处三选一）。
///
/// 牙：① 把委托改回就地 `json!` + broadcast ② 删掉委托调用，或把它挪出这个 impl 块 —— 均转红。
#[test]
fn mark_exit_blocked_delegates_to_the_authoritative_cache_writer() {
    // B0 换锚例外（例外的是**锚**，不是**面**）：钉 façade 是判据本体
    // （`impl ProxyErrorEmitter for AppHandleProxyErrorEmitter` 按 A.5 硬约束永不外移），故锚保持
    // **单文件**档 `crate_*("runtime/proxy.rs")`，不随其余 35 条改宽成递归的 `module_*` —— 面一宽，
    // 「这句委托只准挂在门面上」就能被 `proxy/**` 别处的同名文本顶替。
    // 净化面是另一维：本批把 `crate_source` 换成剥注释的 `crate_code`，只改「注释算不算数」、
    // 不改「覆盖哪些文件」，上面那条例外理由原样成立。
    let emitter_impl = crate::commands::guard_scan::top_level_fn_body(
        &crate_code("runtime/proxy.rs"),
        "impl ProxyErrorEmitter for AppHandleProxyErrorEmitter {",
    );
    assert!(
        emitter_impl.contains("crate::commands::misc::mark_ipinfo_proxy_blocked("),
        "出口无效终态必须经 commands::misc 的权威缓存写入腿落地（只广播不写缓存 ⇒ peek 型消费方读陈旧出口）"
    );

    // 取材面（如实登记）：这里用的是 `module_files` 的**未净化**逐文件原文，本批的换面没有碰它。
    //
    // 别把上一条的理由照搬到这里：`module_code` / `crate_code` 的实现是 `mask_comments`
    // （= `literal_face`），它**保留**字符串 / 原始字符串 / 字符与字节字面量，只抹注释
    // （射程表见 `test_support.rs` 的 `module_code` 文档）。把字面量一起抹空的是**另一个**函数
    // `mask_comments_and_strings`（本文件上方 `production_files` 用的正是它——那条判据扫的是代码
    // 符号，不是载荷键）。所以「净化面把字面量抹空」对本条的针不成立。
    //
    // 今天可以不动它，理由不是「换面会失牙」，而是换了也判不出差别：针是字符串字面量，两个面都
    // 保留；本条又是**负面**断言，未净化只可能误红（吵而可查）、不可能假绿；而 `runtime/proxy/**`
    // 今天没有任何注释写出过 `"proxyBlocked":` 这个带引号加冒号的形状（`proxy.rs` 的散文只提
    // `proxyBlocked` 裸词）⇒ 净化面与原文面逐字同判。换面对本条是纯降噪，不在本批射程内。
    assert!(
        !module_files("runtime/proxy")
            .iter()
            .any(|(_, source)| source.contains("\"proxyBlocked\":")),
        "emitter 侧不得就地拼 ipInfo 载荷：那会绕开 direct 保留 / error 删键 / 缓存写回三条语义，\
             并让载荷形状出现第二个真相源"
    );
}

/// 守卫的守卫：证明扫到的是**真的生产区**，而不是空串 / 被剥光的一片空行。
/// 空输入会让上面的 `sites.len()` 恒为 0 —— 那是「return 型门 = 没门」的形态，只不过这里表现为
/// 数量断言恒红；仍显式钉住正向内容，避免将来有人「修」成 `>= 0` 之类的宽松判据。
#[test]
fn guard_scan_actually_captured_the_production_region() {
    let lines = production_lines();
    assert!(
        lines.len() > 3_000,
        "扫到的生产区只有 {} 行 ⇒ 边界锚点漂了，守卫失去判据",
        lines.len()
    );
    // 按**命中次数**求和，不按「命中行数」计：后者对「同一行写两条腿」或「同一条腿在同一行出现
    // 两次」都只计 1，数目会静默偏小——而偏小的方向恰好与「某条腿被删」这个失败向量同向，
    // 两个变异互相掩护。今天 `proxy.rs` 里无此形态（逐行计与逐次计同为 9），改动不改变今日结果，
    // 只是把「同行两腿互相掩护」这条向量堵上。
    assert_eq!(
        lines
            .iter()
            .map(|l| EXIT_IP_LEGS.iter().filter(|leg| l.contains(*leg)).count())
            .sum::<usize>(),
        KNOWN_EXIT_IP_LEG_SITES,
        "生产区里出口 IP 腿的调用点总数变了：要么有腿没配对失效侧（多），要么某条触发点的腿被删（少）——\
             两种都必须停下来显式裁定，不许让守卫自适应放行"
    );
    // 三种形态各自至少有一个真实调用点 —— 防「把某个 leg 常量留在表里、生产侧其实已删」的假绿：
    // 那种状态下总数断言可以靠另外两种形态凑够，而被删的那条腿永远没人再守。
    for leg in EXIT_IP_LEGS {
        assert!(
            lines.iter().any(|l| l.contains(leg)),
            "出口 IP 腿 `{leg}` 在生产区零调用点 ⇒ 它要么已被删（该同步删表项），要么从未接线"
        );
    }
    // 反向自证：确认剥注释没有把代码一并剥掉（`fn` 定义行本身不带 `self.` 前缀，不计入调用点）。
    assert!(
        lines
            .iter()
            .any(|l| l.contains("fn schedule_exit_ip_refresh")),
        "连方法定义都没扫到 ⇒ 剥注释逻辑把代码也剥了"
    );
}
