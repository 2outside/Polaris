//! [`super`] 的纯逻辑单测：**containment 判据**与**构型分流**的正反两侧。
//!
//! 全部夹具走 [`TestDir`]（进程唯一的临时目录，随栈展开清理）——**只碰副本，绝不碰真实 app
//! 目录**：判据本身要验的是「越界会不会被拒」，拿真目录做夹具等于用生产状态当试验田。
//!
//! release 语义靠给 [`classify`] 传 `dev_build = false` 触发，而不是靠改构型：`cargo test` 下
//! `cfg!(test)` 恒真，不把构型收成入参的话，这一整条腿在任何测试里都跑不到（绿但没有信息量）。

use super::{
    classify, contained_in_trusted_roots, dev_build, EnvPathVerdict, CODE_ENV_PATH_UNTRUSTED,
};
use crate::test_support::TestDir;

use std::path::{Path, PathBuf};

/// 判定用的假变量名：刻意**不叫** `POLARIS_*`，免得本文件的字面量与 `release_escape_hatches`
/// 的名字面扫描发生任何耦合（那道门只扫生产面，但判据不该依赖「我在 tests/ 目录下」）。
const VAR: &str = "HATCH_VAR";

fn write_file(path: &Path) -> PathBuf {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("夹具目录必须可创建");
    }
    std::fs::write(path, b"#!/bin/sh\n").expect("夹具文件必须可写");
    path.to_path_buf()
}

/// release 腿：`classify` 在 `dev_build = false` 下的判定（不产生 `Err` —— 那是 dev 腿专属）。
fn release_verdict(raw: &Path, roots: &[PathBuf]) -> EnvPathVerdict {
    let raw = raw.to_string_lossy().into_owned();
    classify(VAR, Some(&raw), false, roots).expect("release 腿只回落、不硬失败")
}

fn assert_rejected(verdict: &EnvPathVerdict, what: &str) {
    match verdict {
        EnvPathVerdict::Rejected { code, detail } => {
            assert_eq!(
                *code, CODE_ENV_PATH_UNTRUSTED,
                "{what}：拒绝必须带稳定错误码"
            );
            assert!(
                detail.contains(VAR),
                "{what}：日志详情必须点名是哪个变量（{detail}）"
            );
        }
        other => panic!("{what}：必须被拒，实得 {other:?}"),
    }
}

// ── containment 判据：正侧 ────────────────────────────────────────────────

#[test]
fn containment_accepts_a_file_inside_the_root() {
    let dir = TestDir::new("polaris-envtrust-in-");
    let root = dir.join("root");
    let core = write_file(&root.join("core_update").join("sing-box"));

    let canonical = contained_in_trusted_roots(&core, &[root]).expect("根内文件必须被接受");
    assert_eq!(
        canonical,
        core.canonicalize().unwrap(),
        "采纳的必须是 canonical 那一个"
    );
}

#[test]
fn containment_normalises_the_path_before_accepting_it() {
    // 采纳值必须是 canonical：验的是 A、用的是 B 会让整条判据失去意义。
    let dir = TestDir::new("polaris-envtrust-norm-");
    let root = dir.join("root");
    let core = write_file(&root.join("bin").join("sing-box"));
    let noisy = root
        .join("bin")
        .join(".")
        .join("..")
        .join("bin")
        .join("sing-box");

    assert_eq!(
        contained_in_trusted_roots(&noisy, &[root]).expect("绕了一圈仍在根内 → 接受"),
        core.canonicalize().unwrap()
    );
}

// ── containment 判据：反侧（逐条对应一类逃逸形态）──────────────────────────

#[test]
fn containment_rejects_parent_traversal() {
    // `<root>/../<兄弟目录>/evil`：字面前缀判据会放行（串以 `<root>` 开头），canonical 判据不会。
    let dir = TestDir::new("polaris-envtrust-updir-");
    let root = dir.join("root");
    std::fs::create_dir_all(&root).unwrap();
    let outside = write_file(&dir.join("outside").join("evil"));
    let traversal = root.join("..").join("outside").join("evil");

    assert!(
        outside.is_file(),
        "夹具自检：越界目标必须真实存在，否则本条会因『不存在』而假绿"
    );
    assert!(
        contained_in_trusted_roots(&traversal, &[root]).is_none(),
        "目录穿越必须被拒"
    );
}

#[cfg(unix)]
#[test]
fn containment_rejects_a_symlink_escaping_the_root() {
    // 根**内**的一个 symlink 指向根外：不 canonicalize 目标就必然放行 —— 这是 containment
    // 判据存在的核心理由，也是「削弱成字面前缀」那条变异的转红点。
    let dir = TestDir::new("polaris-envtrust-link-");
    let root = dir.join("root");
    std::fs::create_dir_all(&root).unwrap();
    let outside = write_file(&dir.join("outside").join("evil"));
    let link = root.join("sing-box");
    std::os::unix::fs::symlink(&outside, &link).unwrap();

    assert!(
        link.is_file(),
        "夹具自检：symlink 必须指向一个真实文件（否则本条因『不存在』假绿）"
    );
    assert!(
        link.starts_with(&root),
        "夹具自检：symlink 本身确实躺在根内"
    );
    assert!(
        contained_in_trusted_roots(&link, &[root]).is_none(),
        "symlink 逃逸必须被拒"
    );
}

#[test]
fn containment_rejects_a_missing_path() {
    // canonicalize 失败 = 判据不成立 = 拒绝（先验检查失败时宁可什么都不做）。
    let dir = TestDir::new("polaris-envtrust-missing-");
    let root = dir.join("root");
    std::fs::create_dir_all(&root).unwrap();
    let missing = root.join("nope");
    assert!(contained_in_trusted_roots(&missing, &[root]).is_none());
}

#[test]
fn containment_rejects_a_directory() {
    let dir = TestDir::new("polaris-envtrust-dir-");
    let root = dir.join("root");
    let sub = root.join("core_update");
    std::fs::create_dir_all(&sub).unwrap();
    assert!(
        contained_in_trusted_roots(&sub, &[root]).is_none(),
        "目录不是可执行来源"
    );
}

#[test]
fn containment_rejects_a_sibling_sharing_a_literal_prefix() {
    // `<root>-evil/core` 的**字面串**以 `<root>` 开头，但按路径组件它不在根内。
    let dir = TestDir::new("polaris-envtrust-sibling-");
    let root = dir.join("polaris");
    std::fs::create_dir_all(&root).unwrap();
    let sibling = write_file(&dir.join("polaris-evil").join("core"));

    assert!(
        sibling
            .to_string_lossy()
            .starts_with(&*root.to_string_lossy()),
        "夹具自检：字面前缀确实成立（否则这条测不到组件比对）"
    );
    assert!(
        contained_in_trusted_roots(&sibling, &[root]).is_none(),
        "同字面前缀的兄弟目录必须被拒"
    );
}

#[test]
fn containment_rejects_everything_when_there_is_no_root() {
    // 可信根一个都没有（`core_paths` 基目录未注入且 scope 不含随包根）⇒ 只会更严。
    let dir = TestDir::new("polaris-envtrust-noroot-");
    let core = write_file(&dir.join("sing-box"));
    assert!(contained_in_trusted_roots(&core, &[]).is_none());
}

// ── 构型分流 ──────────────────────────────────────────────────────────────

#[test]
fn test_build_is_always_a_dev_build() {
    // 这条钉住的是**真机 `#[ignore]` 验收不受影响**：它们跑在 `cargo test` 下，`cfg!(test)` 恒真
    // ⇒ `dev_build()` 恒真 ⇒ 逃生门走「原样第一优先级」那条腿，与引入信任级前逐字一致。
    // 判据写死在 `cfg!(any(debug_assertions, test))`，`cargo test --release` 同样命中 `test`。
    assert!(dev_build(), "测试构型必须走 dev 腿");
}

#[test]
fn dev_build_keeps_the_escape_hatch_as_first_priority() {
    // dev 腿完全不看可信根：指哪跑哪，且返回**原样**路径（不 canonicalize —— 那会改变既有
    // 断言，如 macOS 上 `/tmp` → `/private/tmp`）。
    let dir = TestDir::new("polaris-envtrust-dev-");
    let core = write_file(&dir.join("anywhere").join("sing-box"));
    let raw = core.to_string_lossy().into_owned();

    assert_eq!(
        classify(VAR, Some(&raw), true, &[]).unwrap(),
        EnvPathVerdict::Accepted(core),
        "dev 构型下逃生门是第一优先级，且路径原样返回"
    );
}

#[test]
fn dev_build_missing_file_is_a_hard_error() {
    let err = classify(VAR, Some("/nonexistent/polaris-core-xyz"), true, &[])
        .expect_err("dev 腿指向不存在的文件必须硬失败，绝不静默回落");
    assert!(err.contains(VAR), "错误必须点名是哪个变量：{err}");
}

#[test]
fn unset_is_not_a_rejection() {
    // 未设 ≠ 被拒：前者不该产生日志噪音，后者必须自曝。
    assert_eq!(
        classify(VAR, None, true, &[]).unwrap(),
        EnvPathVerdict::Unset
    );
    assert_eq!(
        classify(VAR, None, false, &[]).unwrap(),
        EnvPathVerdict::Unset
    );
}

// ── release 语义（构型收成入参才测得到）────────────────────────────────────

#[test]
fn release_accepts_a_path_inside_a_trusted_root() {
    let dir = TestDir::new("polaris-envtrust-rel-ok-");
    let root = dir.join("root");
    let core = write_file(&root.join("core_update").join("sing-box"));

    assert_eq!(
        release_verdict(&core, &[root]),
        EnvPathVerdict::Accepted(core.canonicalize().unwrap())
    );
}

#[test]
fn release_rejects_an_out_of_bounds_path_with_the_stable_error_code() {
    // 越界路径在 release 语义下必须走**拒绝腿**并产出稳定错误码（不是 `Err`、不是静默 `Unset`）。
    let dir = TestDir::new("polaris-envtrust-rel-bad-");
    let root = dir.join("root");
    std::fs::create_dir_all(&root).unwrap();
    let outside = write_file(&dir.join("outside").join("evil"));

    assert_rejected(&release_verdict(&outside, &[root]), "越界路径");
}

#[cfg(unix)]
#[test]
fn release_rejects_symlink_escape_with_the_stable_error_code() {
    let dir = TestDir::new("polaris-envtrust-rel-link-");
    let root = dir.join("root");
    std::fs::create_dir_all(&root).unwrap();
    let outside = write_file(&dir.join("outside").join("evil"));
    let link = root.join("sing-box");
    std::os::unix::fs::symlink(&outside, &link).unwrap();

    assert_rejected(&release_verdict(&link, &[root]), "symlink 逃逸");
}
