# GeoIP 和 GeoSite 数据文件

**简体中文** · [English](geo-rulesets.en.md)

随包内置的 sing-box 规则集（`.srs`，二进制格式），用于路由分流。它们**入库随包分发**，使智能分流、应用分流、地区分流**离线可用——无启动期下载、不会因源 404 FATAL**。这些是出厂种子：运行期拷贝到 `<userData>/rules/`，并可经 app 内「规则资源」在线更新（自动更新 + fswatch 热重载）。

权威清单见 `crates/config-engine/src/user_config/builtin_geo_rulesets.rs`（`builtin_geo_rulesets()`）；
份数由 `src-tauri/build.rs::EXPECTED_SRS_COUNT` 与 `scripts/verify-packaging.mjs inventory` 一同钉住。当前共 **28 个文件（7 geoip + 21 geosite）**：

- **国内基线（3）**——`geoip-cn` · `geosite-cn` · `geosite-geolocation-!cn`。来源：SagerNet [sing-geoip](https://github.com/SagerNet/sing-geoip) / [sing-geosite](https://github.com/SagerNet/sing-geosite)（rule-set 分支）。
- **应用分流预设**——常见应用的 `geosite-*`（youtube、netflix、tiktok、telegram、twitter、instagram、openai、anthropic、category-ai-!cn、google、github、spotify、steam、epicgames、riot、disney）+ 部分 `geoip-*`（netflix、telegram、twitter）。来源：[MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat)（`@sing`）。
- **地区分流（伊朗 / 俄罗斯）**——`geosite-category-ir` · `geosite-category-ru` · `geoip-ir` · `geoip-ru`。来源：MetaCubeX/meta-rules-dat。
- **私有 / 局域网**——`geoip-private` · `geosite-private`（本地/内网直连）。

> 入库：`resources/data/` 下的这些 `.srs` 文件（`.gitignore` 的 `!/resources/data/` 放行）。不入库：`sing-box` 二进制、`libcronet.*`、`dashboard/` —— 由 `scripts/fetch-*.mjs` 拉取，见 `build-and-package.md`。
>
> **本文档不随包分发**：它 2026-08-29 从 `resources/data/` 移到这里 —— 那个目录整个是 `bundle.resources` 条目，放在里面的任何文件都会进四个平台的安装包（`scripts/verify-packaging.mjs inventory` 现在会为此转红）。

## 用途

- **智能分流模式**：中国 IP / 域名直连，其余走代理。
- **应用分流**：按应用 代理 / 直连 / 阻止，依赖应用分流 geo 集。
- **地区分流**：国内直连 / 回国反向，使用地区 geo 集。
- **自定义规则**：在路由规则里经 `res:builtin:<tag>` 或 `rule_set` 引用任一 tag。

## 更新

内置集在 app 内更新（规则资源 → 更新；自动更新默认开启）。如需从官方源手动刷新单个文件，例如：

```bash
curl -L -o geoip-cn.srs https://github.com/SagerNet/sing-geoip/releases/latest/download/geoip-cn.srs
```

## 在 sing-box 配置中使用

```json
{
  "route": {
    "rule_set": [
      { "tag": "geoip-cn", "type": "local", "format": "binary", "path": "/path/to/geoip-cn.srs" },
      { "tag": "geosite-cn", "type": "local", "format": "binary", "path": "/path/to/geosite-cn.srs" }
    ],
    "rules": [
      { "rule_set": ["geoip-cn", "geosite-cn"], "outbound": "direct" }
    ]
  }
}
```
