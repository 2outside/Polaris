use super::super::*;

#[test]
fn plan_from_catalog_id_resolves_mrd_url_and_filename() {
    let item = json!({ "catalogId": "geosite-youtube" });
    let plan = plan_from_item(&item, &[]).expect("catalog 条目应解析");
    assert_eq!(plan.id, "geosite-youtube");
    assert_eq!(plan.category, "geosite");
    assert_eq!(plan.format, RuleResourceFormat::Binary);
    assert_eq!(plan.file_name, "geosite-youtube.srs");
    assert_eq!(
        plan.url,
        "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/youtube.srs"
    );
}

#[test]
fn plan_from_unknown_catalog_id_errs() {
    let item = json!({ "catalogId": "geosite-nonexistent" });
    assert!(plan_from_item(&item, &[]).is_err());
}

#[test]
fn plan_from_url_infers_format_name_and_filename() {
    let item = json!({ "url": "https://example.com/lists/my-rules.json" });
    let plan = plan_from_item(&item, &[]).expect("url 应解析");
    assert_eq!(plan.format, RuleResourceFormat::Source);
    assert_eq!(plan.name, "my-rules");
    assert!(
        plan.file_name.ends_with(".json"),
        "实得: {}",
        plan.file_name
    );
    assert_eq!(plan.category, "custom");
    // .srs 默认 binary。
    let srs = plan_from_item(
        &json!({ "url": "https://example.com/geoip-cn.srs", "name": "cn", "category": "geoip" }),
        &[],
    )
    .unwrap();
    assert_eq!(srs.format, RuleResourceFormat::Binary);
    assert_eq!(srs.name, "cn");
    assert_eq!(srs.category, "geoip");
    assert!(srs.file_name.ends_with(".srs"));
}

#[test]
fn plan_rejects_non_http_and_empty_items() {
    assert!(plan_from_item(&json!({ "url": "file:///etc/passwd" }), &[]).is_err());
    assert!(plan_from_item(&json!({ "url": "ftp://x/y.srs" }), &[]).is_err());
    assert!(plan_from_item(&json!({}), &[]).is_err());
    assert!(plan_from_item(&json!({ "name": "x" }), &[]).is_err());
}

#[test]
fn sanitize_stem_blocks_traversal_and_separators() {
    assert_eq!(sanitize_file_stem("geosite-youtube"), "geosite-youtube");
    assert!(!sanitize_file_stem("../../etc/passwd").contains(".."));
    assert!(!sanitize_file_stem("a/b\\c").contains('/'));
    assert!(!sanitize_file_stem("a/b\\c").contains('\\'));
    assert_eq!(sanitize_file_stem(""), "_");
}

#[test]
fn validate_bytes_enforces_srs_magic_and_json_object() {
    // binary: 需 SRS 魔数。
    assert!(validate_resource_bytes(RuleResourceFormat::Binary, b"SRS\x01\x02").is_ok());
    assert!(validate_resource_bytes(RuleResourceFormat::Binary, b"<html>").is_err());
    assert!(validate_resource_bytes(RuleResourceFormat::Binary, b"").is_err());
    // source: 需 JSON 对象。
    assert!(
        validate_resource_bytes(RuleResourceFormat::Source, br#"{"version":1,"rules":[]}"#).is_ok()
    );
    assert!(validate_resource_bytes(RuleResourceFormat::Source, b"[1,2,3]").is_err());
    assert!(validate_resource_bytes(RuleResourceFormat::Source, b"not json").is_err());
}

#[test]
fn upsert_replaces_by_id_and_appends_new() {
    let mut cfg = json!({ "ruleResources": [
        { "id": "geosite-cn", "name": "old", "category": "geosite", "sourceUrl": "u", "fileName": "geosite-cn.srs", "format": "binary", "size": 1, "downloadedAt": "t" }
    ]});
    let updated = RuleResource {
        id: "geosite-cn".into(),
        name: "new".into(),
        category: "geosite".into(),
        source_url: "u2".into(),
        file_name: "geosite-cn.srs".into(),
        format: RuleResourceFormat::Binary,
        size: 99,
        downloaded_at: "t2".into(),
    };
    let added = RuleResource {
        id: "geoip-us".into(),
        name: "us".into(),
        category: "geoip".into(),
        source_url: "u3".into(),
        file_name: "geoip-us.srs".into(),
        format: RuleResourceFormat::Binary,
        size: 5,
        downloaded_at: "t3".into(),
    };
    upsert_rule_resources(&mut cfg, &[updated, added]);
    let arr = cfg["ruleResources"].as_array().unwrap();
    assert_eq!(arr.len(), 2, "同 id 覆盖不新增，新 id 追加");
    let cn = arr.iter().find(|r| r["id"] == "geosite-cn").unwrap();
    assert_eq!(cn["name"], "new");
    assert_eq!(cn["size"], 99);
    assert!(arr.iter().any(|r| r["id"] == "geoip-us"));
}

// ── P2：current_iso 须产出合法 ISO（旧实现把 epoch 秒塞进秒字段 → 非法）──

#[test]
fn current_iso_produces_valid_epoch_not_buggy_seconds_field() {
    // 已知 epoch 1_700_000_000s（2023-11-14T22:13:20Z）→ 精确 ISO（毫秒精度）。
    assert_eq!(
        polaris_stats_engine::created_at_to_rfc3339(1_700_000_000_000),
        Some("2023-11-14T22:13:20.000Z".to_string())
    );
    // current_iso() 现产出合法 ISO：绝不再是旧 bug 的「1970-01-01T00:00:<整个 epoch 秒>Z」。
    let now = current_iso();
    assert!(
        !now.starts_with("1970-01-01T00:00:"),
        "current_iso 不得把 epoch 秒塞进秒字段（旧 bug），实得: {now}"
    );
    assert!(
        now.ends_with('Z') && now.len() >= 20,
        "current_iso 须为合法 ISO，实得: {now}"
    );
}

// ── P3：plan_from_resource 须在信任边界清洗被篡改的 fileName ──

#[test]
fn plan_from_resource_sanitizes_tampered_file_name() {
    let res_dir = std::path::Path::new("/home/u/.config/polaris/rule-resource");
    let mk = |file_name: &str| RuleResource {
        id: "x".into(),
        name: "x".into(),
        category: "c".into(),
        source_url: "https://e/x.srs".into(),
        file_name: file_name.into(),
        format: RuleResourceFormat::Binary,
        size: 1,
        downloaded_at: "t".into(),
    };

    // 相对穿越 `../../.bashrc`：穿越序列 + 分隔符须被清除。
    let plan = plan_from_resource(&mk("../../.bashrc"));
    assert!(
        !plan.file_name.contains(".."),
        "穿越序列须消除: {}",
        plan.file_name
    );
    assert!(
        !plan.file_name.contains('/'),
        "分隔符须清除: {}",
        plan.file_name
    );

    // 绝对路径 `/etc/cron.d/evil`：Path::join(绝对) 会整段替换 → 逃逸（旧行为）。清洗后须仍落在 res_dir 内。
    let plan_abs = plan_from_resource(&mk("/etc/cron.d/evil"));
    assert!(
        !plan_abs.file_name.starts_with('/'),
        "不得保留绝对路径前导斜杠"
    );
    let dest = res_dir.join(&plan_abs.file_name);
    assert!(
        dest.starts_with(res_dir),
        "绝对 fileName 清洗后须仍在资源目录内，实得: {dest:?}"
    );

    // 合法 fileName 幂等（不破坏正常重下载）。
    assert_eq!(
        plan_from_resource(&mk("geosite-cn.srs")).file_name,
        "geosite-cn.srs"
    );
}

// ── P8：redownload / update_all 区分「不在册」与「在册但结构非法」，不静默丢弃坏项 ──

#[test]
fn resolve_registered_resource_distinguishes_missing_malformed_and_ok() {
    let arr = vec![
        json!({ "id": "geosite-cn", "name": "CN", "category": "geosite", "sourceUrl": "https://e/cn.srs", "fileName": "geosite-cn.srs", "format": "binary", "size": 1, "downloadedAt": "t" }),
        // 结构非法：缺 sourceUrl/fileName/size/downloadedAt。
        json!({ "id": "broken", "name": "B", "format": "binary" }),
    ];
    // 命中且合法 → Ok。
    assert_eq!(
        resolve_registered_resource(&arr, "geosite-cn").unwrap().id,
        "geosite-cn"
    );
    // 不在册 → NOT_FOUND。
    let missing = resolve_registered_resource(&arr, "ghost").expect_err("不在册");
    assert_eq!(missing["errorCode"], ERR_RESOURCE_NOT_FOUND);
    assert_eq!(missing["ok"], false);
    // 在册但结构非法 → BAD_ITEM（**非 NOT_FOUND**，P8 修复点）；保留 id 供前端定位。
    let malformed = resolve_registered_resource(&arr, "broken").expect_err("结构非法");
    assert_eq!(malformed["errorCode"], ERR_RESOURCE_BAD_ITEM);
    assert_ne!(malformed["errorCode"], ERR_RESOURCE_NOT_FOUND);
    assert_eq!(malformed["id"], "broken");
}

#[test]
fn parse_resource_entry_flags_malformed_as_failed_item() {
    // update_all 据它把坏条目报成失败项（旧 filter_map(.ok()) 会静默丢弃 → 既不更新也不出现在结果里）。
    let good = json!({ "id": "ok", "name": "OK", "category": "c", "sourceUrl": "https://e/a.srs", "fileName": "ok.srs", "format": "binary", "size": 1, "downloadedAt": "t" });
    assert!(parse_resource_entry(&good).is_ok());
    let bad = json!({ "id": "b", "name": "B" });
    let err = parse_resource_entry(&bad).expect_err("缺字段应判结构非法");
    assert_eq!(err["errorCode"], ERR_RESOURCE_BAD_ITEM);
    assert_eq!(err["ok"], false);
    assert_eq!(err["id"], "b");
    assert_eq!(err["name"], "B");
}

// ── 回环真 socket 门（真 reqwest 打回环，不碰宿主网络；对齐 subscription production_gate）──

mod loopback {
    use super::*;
    use std::future::Future;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener};
    use std::thread;

    use crate::runtime::http::HttpRuntime;

    fn spawn_once(status_line: &'static str, body: Vec<u8>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind 回环端口");
        let addr = listener.local_addr().expect("取端口");
        thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf);
                let mut resp = format!(
                    "HTTP/1.1 {status_line}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .into_bytes();
                resp.extend_from_slice(&body);
                let _ = sock.write_all(&resp);
                let _ = sock.flush();
            }
        });
        addr
    }

    /// mock DnsLookup：把 hostname 钉到指定 IP（放行/拒绝由 IP 是否内网决定）。
    struct FixedLookup(&'static str);
    impl DnsLookup for FixedLookup {
        fn lookup_all(
            &self,
            _host: &str,
        ) -> impl Future<Output = Result<Vec<String>, String>> + Send {
            let ip = self.0.to_string();
            async move { Ok(vec![ip]) }
        }
    }

    #[tokio::test]
    async fn fetches_srs_over_loopback_and_validates_magic() {
        let mut srs = b"SRS".to_vec();
        srs.extend_from_slice(&[0x01, 0x00, 0xde, 0xad]);
        let addr = spawn_once("200 OK", srs);
        // 真 client，DNS 钉定：传输落回环 server；guard 判定对象是公网 IP → 放行（guard 真跑）。
        let client = HttpRuntime::with_resolve_overrides(&[("res.example.com", addr)]).unwrap();
        let lookup = FixedLookup("93.184.216.34");
        let bytes = fetch_resource_bytes(
            &client,
            &lookup,
            "http://res.example.com/geosite-cn.srs",
            RuleResourceFormat::Binary,
        )
        .await
        .expect("回环 SRS 下载应成功");
        assert_eq!(&bytes[..3], b"SRS");
    }

    #[tokio::test]
    async fn rejects_non_srs_body_for_binary() {
        let addr = spawn_once("200 OK", b"<html>not a rule set</html>".to_vec());
        let client = HttpRuntime::with_resolve_overrides(&[("res.example.com", addr)]).unwrap();
        let lookup = FixedLookup("93.184.216.34");
        let err = fetch_resource_bytes(
            &client,
            &lookup,
            "http://res.example.com/x.srs",
            RuleResourceFormat::Binary,
        )
        .await
        .expect_err("非 SRS 内容必须被魔数校验拒");
        assert!(
            err.contains("SRS") || err.contains("srs"),
            "错误应点明魔数，实得: {err}"
        );
    }

    #[tokio::test]
    async fn non_2xx_status_is_error() {
        let addr = spawn_once("404 Not Found", b"nope".to_vec());
        let client = HttpRuntime::with_resolve_overrides(&[("res.example.com", addr)]).unwrap();
        let lookup = FixedLookup("93.184.216.34");
        let err = fetch_resource_bytes(
            &client,
            &lookup,
            "http://res.example.com/x.srs",
            RuleResourceFormat::Binary,
        )
        .await
        .expect_err("404 必须失败");
        assert!(err.contains("404"), "实得: {err}");
    }

    #[tokio::test]
    async fn ssrf_guard_blocks_internal_ip_on_production_path() {
        let addr = spawn_once("200 OK", b"SRS\x01".to_vec());
        let client = HttpRuntime::with_resolve_overrides(&[("res.example.com", addr)]).unwrap();
        // hostname 解析到云元数据地址（内网）→ guard 必拒（防 SSRF）。
        let lookup = FixedLookup("169.254.169.254");
        let err = fetch_resource_bytes(
            &client,
            &lookup,
            "http://res.example.com/x.srs",
            RuleResourceFormat::Binary,
        )
        .await
        .expect_err("内网 IP 必须被 SSRF guard 拒");
        assert!(!err.is_empty(), "SSRF 拒绝须带原因");
    }

    #[tokio::test]
    async fn download_and_store_writes_file_and_reports_existed_before() {
        let mut srs = b"SRS".to_vec();
        srs.extend_from_slice(&[0x07, 0x08]);
        let addr = spawn_once("200 OK", srs.clone());
        let client = HttpRuntime::with_resolve_overrides(&[("res.example.com", addr)]).unwrap();
        let lookup = FixedLookup("93.184.216.34");
        let dir = std::env::temp_dir().join(format!("polaris-resdl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let plan = ResourcePlan {
            id: "geosite-test".into(),
            name: "test".into(),
            category: "geosite".into(),
            url: "http://res.example.com/geosite-test.srs".into(),
            fetch_url: "http://res.example.com/geosite-test.srs".into(),
            file_name: "geosite-test.srs".into(),
            format: RuleResourceFormat::Binary,
        };
        let outcome = download_and_store(&client, &lookup, &plan, &dir).await;
        match outcome {
            DownloadOutcome::Stored {
                resource,
                existed_before,
            } => {
                assert!(!existed_before, "首次下载 existedBefore 应为 false");
                assert_eq!(resource.size, srs.len() as u64);
                let landed = std::fs::read(dir.join("geosite-test.srs")).expect("文件应落盘");
                assert_eq!(landed, srs, "落盘字节须与下载字节一致");
            }
            DownloadOutcome::Failed { message, .. } => panic!("应成功，实得: {message}"),
            DownloadOutcome::Cancelled => panic!("未取消却报了取消"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── 进度可见性（后台腿静默）+ 下载取消 ──────────────────────────────────

    /// 记录式进度落点：把每帧存下来，供断言「静默腿真的一帧不发」。
    #[derive(Default)]
    struct RecordingSink {
        frames: std::sync::Mutex<Vec<Value>>,
    }
    impl RecordingSink {
        fn statuses(&self) -> Vec<String> {
            self.frames
                .lock()
                .unwrap()
                .iter()
                .filter_map(|f| f.get("status").and_then(Value::as_str).map(str::to_string))
                .collect()
        }
    }
    impl ProgressSink for RecordingSink {
        fn emit(&self, frame: Value) {
            self.frames.lock().unwrap().push(frame);
        }
    }

    /// 生产落点的静默判定（`BroadcastSink` 的 `mode` 分支）套在记录器上验：Silent → 零帧。
    struct ModedRecordingSink {
        mode: ProgressMode,
        inner: RecordingSink,
    }
    impl ProgressSink for ModedRecordingSink {
        fn emit(&self, frame: Value) {
            if self.mode == ProgressMode::Silent {
                return; // 与 BroadcastSink::emit 同一条判定
            }
            self.inner.emit(frame);
        }
    }

    fn plan_for(id: &str, addr: SocketAddr) -> ResourcePlan {
        let _ = addr;
        let url = format!("http://res.example.com/{id}.srs");
        ResourcePlan {
            id: id.into(),
            name: format!("test-{id}"),
            category: "geosite".into(),
            fetch_url: url.clone(),
            url,
            file_name: format!("{id}.srs"),
            format: RuleResourceFormat::Binary,
        }
    }

    fn tmp_res_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "polaris-res-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |x| x.as_nanos())
        ));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    /// 手动腿（`ProgressMode::Live`）：downloading + done 两帧齐发。
    ///
    /// **变异锁**：把 `download_with_progress` 开头那帧 `downloading` 删掉 → 本断言转红。
    #[tokio::test]
    async fn live_mode_emits_downloading_and_done_frames() {
        let mut srs = b"SRS".to_vec();
        srs.extend_from_slice(&[0x11, 0x22]);
        let addr = spawn_once("200 OK", srs);
        let client = HttpRuntime::with_resolve_overrides(&[("res.example.com", addr)]).unwrap();
        let sink = ModedRecordingSink {
            mode: ProgressMode::Live,
            inner: RecordingSink::default(),
        };
        let dir = tmp_res_dir("live");
        let plan = plan_for("live-res", addr);
        let outcome =
            download_with_progress(&sink, &client, &FixedLookup("93.184.216.34"), &plan, &dir)
                .await;
        assert!(
            matches!(outcome, DownloadOutcome::Stored { .. }),
            "应下载成功"
        );
        assert_eq!(
            sink.inner.statuses(),
            vec!["downloading".to_string(), "done".to_string()],
            "手动腿必须逐阶段发帧"
        );
        // 帧内 id/name 由 plan 补齐（前端按 id 索引进度表，漏了就永远匹配不上行）。
        let first = sink.inner.frames.lock().unwrap()[0].clone();
        assert_eq!(first["id"], "live-res");
        assert_eq!(first["name"], "test-live-res");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 后台调度腿（`ProgressMode::Silent`）：**一帧都不发**，但下载本身照常完成并落盘。
    ///
    /// **变异锁（本轮要求的变异验证之一）**：把 `BroadcastSink::emit` /
    /// `ModedRecordingSink::emit` 里的 `if mode == Silent { return; }` 删掉（= 后台腿改回推事件）
    /// → 帧数变 2 → 本断言转红。
    #[tokio::test]
    async fn silent_mode_emits_nothing_but_still_downloads() {
        let mut srs = b"SRS".to_vec();
        srs.extend_from_slice(&[0x33, 0x44]);
        let addr = spawn_once("200 OK", srs.clone());
        let client = HttpRuntime::with_resolve_overrides(&[("res.example.com", addr)]).unwrap();
        let sink = ModedRecordingSink {
            mode: ProgressMode::Silent,
            inner: RecordingSink::default(),
        };
        let dir = tmp_res_dir("silent");
        let plan = plan_for("silent-res", addr);
        let outcome =
            download_with_progress(&sink, &client, &FixedLookup("93.184.216.34"), &plan, &dir)
                .await;
        assert!(
            matches!(outcome, DownloadOutcome::Stored { .. }),
            "静默只影响事件，不影响下载本身"
        );
        assert!(
            sink.inner.statuses().is_empty(),
            "后台腿必须零帧，实得: {:?}",
            sink.inner.statuses()
        );
        let landed = std::fs::read(dir.join("silent-res.srs")).expect("静默腿仍须真落盘");
        assert_eq!(landed, srs);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 失败帧走 `status:"error"`（与 cancelled 分流的对照组）。
    #[tokio::test]
    async fn failure_emits_error_frame_with_code() {
        let addr = spawn_once("500 Server Error", b"boom".to_vec());
        let client = HttpRuntime::with_resolve_overrides(&[("res.example.com", addr)]).unwrap();
        let sink = RecordingSink::default();
        let dir = tmp_res_dir("fail");
        let plan = plan_for("fail-res", addr);
        let outcome =
            download_with_progress(&sink, &client, &FixedLookup("93.184.216.34"), &plan, &dir)
                .await;
        assert!(matches!(outcome, DownloadOutcome::Failed { .. }));
        assert_eq!(
            sink.statuses(),
            vec!["downloading".to_string(), "error".to_string()]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── gh 加速：镜像优先 + 失败回退原址（真 socket，两台回环 server）─────────────

    /// 加速前缀命中时**先打镜像**：镜像返有效 SRS → 直接成功，原址那台一次都不被碰。
    ///
    /// **变异锁**：把 `download_and_store` 的首发地址改回 `plan.url`（= 不套加速）→ 镜像 server
    /// 收不到请求、原址 server 被打，`landed` 内容变成 DIRECT 的字节 → 断言转红。
    #[tokio::test]
    async fn mirror_is_tried_first_when_gh_proxy_configured() {
        let mut mirror_body = b"SRS".to_vec();
        mirror_body.extend_from_slice(b"MIRROR");
        let mut direct_body = b"SRS".to_vec();
        direct_body.extend_from_slice(b"DIRECT");
        let mirror = spawn_once("200 OK", mirror_body.clone());
        let direct = spawn_once("200 OK", direct_body);
        let client = HttpRuntime::with_resolve_overrides(&[
            ("mirror.example.com", mirror),
            ("raw.githubusercontent.com", direct),
        ])
        .unwrap();
        let dir = tmp_res_dir("ghproxy-hit");
        let plan = gh_plan("gh-hit").with_gh_proxy("http://mirror.example.com/");
        assert_ne!(plan.fetch_url, plan.url, "前置条件：本例须真套上前缀");
        let outcome = download_and_store(&client, &FixedLookup("93.184.216.34"), &plan, &dir).await;
        assert!(
            matches!(outcome, DownloadOutcome::Stored { .. }),
            "镜像应下成功"
        );
        let landed = std::fs::read(dir.join("gh-hit.srs")).expect("须落盘");
        assert_eq!(
            landed, mirror_body,
            "落盘的必须是镜像返回的字节（= 走了镜像）"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 镜像挂了（500）→ **自动回退原址**，仍拿到资源（设置页 `ghProxyHint` 明写的承诺）。
    ///
    /// **变异锁**：删掉 `download_and_store` 里 `if attempt.is_err() && fetch_url != url` 的回退腿
    /// → 结果变 `Failed`、文件不落盘 → 本断言转红。
    #[tokio::test]
    async fn falls_back_to_origin_when_mirror_fails() {
        let mut direct_body = b"SRS".to_vec();
        direct_body.extend_from_slice(b"DIRECT");
        let mirror = spawn_once("500 Server Error", b"boom".to_vec());
        let direct = spawn_once("200 OK", direct_body.clone());
        let client = HttpRuntime::with_resolve_overrides(&[
            ("mirror.example.com", mirror),
            ("raw.githubusercontent.com", direct),
        ])
        .unwrap();
        let dir = tmp_res_dir("ghproxy-fallback");
        let plan = gh_plan("gh-fb").with_gh_proxy("http://mirror.example.com/");
        let outcome = download_and_store(&client, &FixedLookup("93.184.216.34"), &plan, &dir).await;
        assert!(
            matches!(outcome, DownloadOutcome::Stored { .. }),
            "镜像失败须回退原址，不得直接判失败"
        );
        let landed = std::fs::read(dir.join("gh-fb.srs")).expect("回退腿也须真落盘");
        assert_eq!(landed, direct_body);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 未配加速时**不重试**：原址失败即失败（同址重试无意义，别把一次失败变成两次超时）。
    #[tokio::test]
    async fn no_prefix_means_single_attempt() {
        let direct = spawn_once("500 Server Error", b"boom".to_vec());
        let client =
            HttpRuntime::with_resolve_overrides(&[("raw.githubusercontent.com", direct)]).unwrap();
        let dir = tmp_res_dir("ghproxy-none");
        let plan = gh_plan("gh-none").with_gh_proxy("");
        assert_eq!(plan.fetch_url, plan.url);
        let outcome = download_and_store(&client, &FixedLookup("93.184.216.34"), &plan, &dir).await;
        assert!(matches!(outcome, DownloadOutcome::Failed { .. }));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 源地址钉在 `raw.githubusercontent.com`（规则资源的真实默认源）的计划。
    fn gh_plan(id: &str) -> ResourcePlan {
        let url = format!("http://raw.githubusercontent.com/x/{id}.srs");
        ResourcePlan {
            id: id.into(),
            name: id.into(),
            category: "geosite".into(),
            fetch_url: url.clone(),
            url,
            file_name: format!("{id}.srs"),
            format: RuleResourceFormat::Binary,
        }
    }

    /// 接受连接后**不回应**的服务端（模拟慢/挂死的下载源，供取消测试）。
    /// 持有 listener 到测试结束（返回 JoinHandle 的 sender 端由线程 park 住）。
    fn spawn_hanging() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind 回环端口");
        let addr = listener.local_addr().expect("取端口");
        thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf);
                // 收下请求后什么都不回：连接一直挂着，直到测试结束进程回收。
                thread::sleep(std::time::Duration::from_secs(60));
                drop(sock);
            }
        });
        addr
    }

    /// **取消真的中断在途下载**（不是「标记取消后继续下完」）。
    ///
    /// 服务端收下请求后永不响应；若无取消，`download_with_progress` 会挂到
    /// `RULE_RESOURCE_TIMEOUT_MS`(30s)。本测把整体超时压到 8s：
    /// - **变异锁（本轮要求的变异验证之二）**：删掉 `tokio::select!` 的取消分支（退回直接
    ///   `download_and_store(...).await`）→ 8s 内不返回 → 本测超时转红。
    /// - 同时断言：结果为 `Cancelled`、发了 `cancelled` 帧、**没有落盘**、`cancel_inflight` 计数为 1。
    #[tokio::test]
    async fn cancel_aborts_inflight_download_and_writes_nothing() {
        let addr = spawn_hanging();
        let client = HttpRuntime::with_resolve_overrides(&[("res.example.com", addr)]).unwrap();
        let dir = tmp_res_dir("cancel");
        let plan = plan_for("cancel-res", addr);
        let sink = std::sync::Arc::new(RecordingSink::default());

        let sink_bg = sink.clone();
        let dir_bg = dir.clone();
        let task = tokio::spawn(async move {
            download_with_progress(
                sink_bg.as_ref(),
                &client,
                &FixedLookup("93.184.216.34"),
                &plan,
                &dir_bg,
            )
            .await
        });

        // 等登记落表（登记在首个 await 之前同步完成，故轮询极快命中）。
        let mut cancelled = 0usize;
        for _ in 0..200 {
            cancelled = cancel_inflight("cancel-res");
            if cancelled > 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(cancelled, 1, "应恰好中止一条在途下载");

        let outcome = tokio::time::timeout(std::time::Duration::from_secs(8), task)
            .await
            .expect("取消后必须立刻返回（超时=取消分支没接线）")
            .expect("下载任务不应 panic");
        assert!(
            matches!(outcome, DownloadOutcome::Cancelled),
            "结果须为 Cancelled"
        );
        assert_eq!(
            sink.statuses(),
            vec!["downloading".to_string(), "cancelled".to_string()],
            "须发 cancelled 帧（前端据此清行，而非留一个永远转圈的 spinner）"
        );
        assert!(!dir.join("cancel-res.srs").is_file(), "取消的下载不得落盘");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 没有在途下载时取消：如实返回 0（不伪装成功）。
    #[test]
    fn cancel_with_no_inflight_reports_zero() {
        assert_eq!(cancel_inflight("nobody-is-downloading-this"), 0);
    }

    /// 取消是 per-id 的：只中止目标 id，别人的在途下载不受影响。
    #[tokio::test]
    async fn cancel_only_targets_requested_id() {
        let addr = spawn_hanging();
        let client = HttpRuntime::with_resolve_overrides(&[("res.example.com", addr)]).unwrap();
        let dir = tmp_res_dir("cancel-iso");
        let plan = plan_for("keep-me", addr);
        let sink = std::sync::Arc::new(RecordingSink::default());
        let sink_bg = sink.clone();
        let dir_bg = dir.clone();
        let task = tokio::spawn(async move {
            download_with_progress(
                sink_bg.as_ref(),
                &client,
                &FixedLookup("93.184.216.34"),
                &plan,
                &dir_bg,
            )
            .await
        });
        // 等 keep-me 登记完成后取消**另一个** id → 不应命中。
        for _ in 0..200 {
            let registered = cancel_registry()
                .lock()
                .map(|r| r.values().any(|(id, _)| id == "keep-me"))
                .unwrap_or(false);
            if registered {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(cancel_inflight("some-other-id"), 0, "别的 id 不该被误伤");
        assert_eq!(cancel_inflight("keep-me"), 1, "目标 id 仍在途 → 可被取消");
        let _ = tokio::time::timeout(std::time::Duration::from_secs(8), task).await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
