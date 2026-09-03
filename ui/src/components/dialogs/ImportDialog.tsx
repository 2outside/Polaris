/**
 * ImportDialog —— 手动导入弹窗（粘贴文本 / 本地文件，原型 #add-dialog :2488-2510）。
 *
 * 流程（**两步**）：粘贴分享链接 / 订阅 URL / Base64 / Clash → 客户端轻量识别（复用
 * `domain/protocol-url-schemes.ts` 的 `isSupportedShareUrl`，不重写）→ 点「解析」走真后端
 * `local_import_parse`（离线解析，src-tauri/src/commands/subscription.rs）→ **停在结果预览**
 * （计数 + 告警 + 节点清单）→ 点「导入 N 项」才 `server.addBulk` 批量入库。
 *
 * 拆成两步是因为后端一直在返回 `stats` 与 `warnings`，而此前这里把它们**整个丢掉**：
 * 「4 个因缺字段没进来」「6 个协议本内核不认、已透传成 custom」这些后端算得完全正确的事实，
 * 用户一次都看不到，点完只知道「成功了」。
 *
 * **文件选择两条路径**：
 *  - 点击拖放区 → `local_import_pick_file`（tauri-plugin-dialog 原生选择器 + 读内容回传，取消静默，
 *    超限/读失败提示）；拖拽 → 客户端 `FileReader`（webview 放行时可用）。两者殊途同归到 `content`。
 *  - `local_import_parse` 0 节点 / 不可识别 → 后端 throw → 前端 catch 显错，弹窗保持打开。
 *
 * URL 识别为订阅（checklist R7-5/6）：单行裸订阅 URL → 非阻断提示引导「添加订阅」（`sub` 弹窗为 D3，
 * union kind 已存在，open 即可，落地后渲染）。
 *
 * props 签名由 stub 冻结：`ImportDialog()`（无 props，恒新增态）。
 */

import { useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/ipc';
import type { ImportParseResult } from '@/contracts/types';
import { isSupportedShareUrl } from '@/domain/protocol-url-schemes';
import { admitMeshSingletons } from '@/domain/endpoint-routes';
import { useAppStore, useEffectiveServers } from '@/store/app-store';
import { useStagedConfigStore } from '@/store/staged-config-store';
import { useStagingActive } from '@/store/use-staging-active';
import { editRoute } from '@/lib/staged-config';
import { toast } from '@/lib/error-handler';
import { Modal } from './Modal';
import { useDialogStore } from './dialog-store';
import {
  canPublishLocalImportParse,
  canPublishLocalImportFileRead,
  localImportCloseLocked,
  localImportPrimaryActionDisabled,
} from './local-import-parse-state';
import { readLocalImportFile } from './local-import-file-read';

type Source = 'share' | 'file';

/** 客户端轻量识别（预览用；权威解析在 Rust local_import_parse）。 */
interface Detection {
  kind: 'links' | 'base64' | 'clash' | 'subscription' | 'unknown' | 'empty';
  linkCount: number;
}

const BASE64_RE = /^[A-Za-z0-9+/=\s]+$/;

function detect(text: string): Detection {
  const trimmed = text.trim();
  if (!trimmed) return { kind: 'empty', linkCount: 0 };

  const lines = trimmed.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  const links = lines.filter((l) => isSupportedShareUrl(l));
  if (links.length > 0) return { kind: 'links', linkCount: links.length };

  // 单行裸订阅 URL（http(s)、无内联凭据 @、无 #name 片段）→ 疑似订阅
  if (
    lines.length === 1 &&
    /^https?:\/\/\S+$/i.test(trimmed) &&
    !trimmed.includes('@') &&
    !trimmed.includes('#')
  ) {
    return { kind: 'subscription', linkCount: 0 };
  }

  if (/(^|\n)\s*proxies\s*:/.test(trimmed)) return { kind: 'clash', linkCount: 0 };
  if (!trimmed.includes('\n') && BASE64_RE.test(trimmed) && trimmed.length >= 24) {
    return { kind: 'base64', linkCount: 0 };
  }
  return { kind: 'unknown', linkCount: 0 };
}

export function ImportDialog({ instanceId, onAdded }: { instanceId: string; onAdded?: () => void }) {
  const { t } = useTranslation();
  const open = useDialogStore((s) => s.open);
  const closeInstance = useDialogStore((s) => s.closeInstance);
  const hasInstance = useDialogStore((s) => s.hasInstance);
  // 展示面：单例槽判据必须含暂存节点 —— 否则暂存了一个 WARP 还能再导入第二个，重放后配置非法。
  const servers = useEffectiveServers();
  const stagingEnabled = useStagingActive();
  const stage = useStagedConfigStore((s) => s.stage);
  const loadConfig = useAppStore((s) => s.loadConfig);

  const [source, setSource] = useState<Source>('share');
  const [content, setContent] = useState('');
  const [dragOver, setDragOver] = useState(false);
  const [fileHint, setFileHint] = useState<string | null>(null);
  /** Parsing has no write side effect and may be abandoned by closing the dialog. */
  const [parsing, setParsing] = useState(false);
  /** addBulk + force refresh is close-critical: never leave its continuation orphaned. */
  const [importing, setImporting] = useState(false);
  /** 解析结果预览。`null` = 还没解析（或内容已改动，旧结果作废）。 */
  const [preview, setPreview] = useState<ImportParseResult | null>(null);
  const parseGeneration = useRef(0);
  const contentRef = useRef('');

  const det = detect(content);

  const onContentChange = (v: string) => {
    parseGeneration.current += 1;
    contentRef.current = v;
    setContent(v);
    // 内容一改，上一次的解析结果就不再描述它 —— 留着会让用户对着旧预览按「确认导入」。
    setPreview(null);
  };

  const onSourceChange = (next: Source) => {
    if (next === source) return;
    parseGeneration.current += 1;
    setSource(next);
    setPreview(null);
  };

  const closeImportDialog = () => {
    // The bounded backend executor may finish after close, but its result is no longer ours.
    parseGeneration.current += 1;
    closeInstance(instanceId);
  };

  const beginFileRead = () => {
    // A fresh file intent invalidates an earlier drop/picker/parse result before its bytes arrive.
    parseGeneration.current += 1;
    setPreview(null);
    return { generation: parseGeneration.current };
  };

  const canPublishFileRead = (attempt: { generation: number }) => canPublishLocalImportFileRead(attempt, {
    generation: parseGeneration.current,
    hasInstance: hasInstance(instanceId),
  });

  const readFiles = (files: FileList | null) => {
    const file = files?.[0];
    if (!file) return;
    const attempt = beginFileRead();
    void readLocalImportFile(file).then((result) => {
      if (!canPublishFileRead(attempt)) return;
      if (result.kind === 'too_large') {
        setFileHint(t('import.fileTooLarge'));
        return;
      }
      if (result.kind === 'failed') {
        setFileHint(t('import.fileReadFail'));
        return;
      }
      onContentChange(result.text);
      onSourceChange('share');
      setFileHint(null);
    });
  };

  const pickFile = async () => {
    const attempt = beginFileRead();
    setFileHint(null);
    try {
      const r = await api.localImport.pickFile();
      if (!canPublishFileRead(attempt)) return;
      if (r.canceled) return; // 用户取消 → 静默（对齐 上游）
      if (r.error === 'too_large') {
        setFileHint(t('import.fileTooLarge'));
        return;
      }
      if (r.error || r.content == null) {
        setFileHint(t('import.fileReadFail'));
        return;
      }
      onContentChange(r.content);
      onSourceChange('share');
    } catch (e) {
      if (!canPublishFileRead(attempt)) return;
      // 选择器/IPC 的诊断里可能带本地路径；可见提示固定走既有五语键，原文只留日志。
      console.error('[ImportDialog] pick file failed:', e);
      setFileHint(t('import.fileReadFail'));
    }
  };

  const requestClose = () => {
    if (importing) return;
    if (content.trim()) {
      const confirmId = open({
        kind: 'confirm',
        payload: {
          title: t('import.discardTitle'),
          message: t('import.discardMsg'),
          confirmLabel: t('node.discard'),
          danger: true,
          onConfirm: () => {
            closeInstance(confirmId);
            closeImportDialog();
          },
        },
      });
    } else {
      closeImportDialog();
    }
  };

  /**
   * 第一步：解析并**停在预览**，不入库。
   *
   * 为什么要拆成两步：后端一直在返回 `stats`（imported / unsupported / skipped / failed）与
   * `warnings`，而此前这个弹窗把它们**整个丢掉**，只在「撞上单例槽」时报一句。于是
   * 「37 个节点里 4 个因缺字段被丢了」「6 个协议本内核不认、已透传成 custom」这些**后端算得
   * 完全正确**的事实，用户一次都看不到 —— 点完导入只知道「成功了」。
   *
   * 文案不新造：预览阶段这批键（`parse` / `parsed` / `nodesTitle` / `unsupportedBadge` /
   * `unsupportedTip` / `skippedTitle` / `submitN {{count}}` / `resultUnsupported`）五语齐备、
   * **本来就在设计里**，只是移植时整套躺进了一个零消费点的 `localImport.*` 命名空间。已并入 `import.*`。
   */
  const handleParse = async () => {
    const input = content;
    const text = input.trim();
    if (!text) {
      toast.error(t('import.errEmpty'));
      return;
    }
    const attempt = { generation: parseGeneration.current, input };
    setParsing(true);
    try {
      const result = await api.localImport.parse(text); // 0 节点 / 不可识别 → throw
      if (!canPublishLocalImportParse(attempt, {
        generation: parseGeneration.current,
        input: contentRef.current,
        hasInstance: hasInstance(instanceId),
      })) return;
      if (!result.nodes.length) {
        toast.error(t('import.errNoNodes'));
        return;
      }
      setPreview(result);
    } catch (e) {
      if (!canPublishLocalImportParse(attempt, {
        generation: parseGeneration.current,
        input: contentRef.current,
        hasInstance: hasInstance(instanceId),
      })) return;
      console.error('[ImportDialog] preview failed:', e);
      toast.error(t('import.failed'));
    } finally {
      if (hasInstance(instanceId)) setParsing(false);
    }
  };

  /** 第二步：把预览里那批节点真正入库。 */
  const handleImport = async () => {
    const result = preview;
    if (!result) return;
    setImporting(true);
    try {
      // 组网单例硬闸门·**逐条**（`admitMeshSingletons` 让准入者即刻占槽，同一批里的第二个 WARP
      // 也拦得住）。整批拒绝是错的：一条撞槽的节点不该连累同批其余正常节点，故过滤 + 如实报跳过数。
      // 今天 net-stack 的三个解析器（clash/singbox/xray）都跳过 wireguard，本闸门恒不命中；但
      // `detect_format` 已为 sing-box `endpoints[]`（wireguard/tailscale）留了分支，那条一旦接通，
      // 外部内容就能直接灌进 `server:addBulk`——闸门必须先于它就位。
      const { admitted, rejected } = admitMeshSingletons(result.nodes, servers);
      if (!admitted.length) {
        toast.error(
          t('nodes.importSingletonAllSkipped')
        );
        return;
      }
      // 配置暂存闸门（与 NodeDialog 同形）。解析已经在 `localImport.parse` 里做完，`addBulk` 本身
      // 是**纯 `servers` 写**、无副作用 ⇒ 走默认腿。批量导入 ⇒ 逐节点一条条目：整批一条的话
      // 「逐条撤销」就退化成「要么全留要么全撤」，而这正是导入最需要挑挑拣拣的场景。
      const staged = editRoute('servers', stagingEnabled) === 'staged';
      if (staged) {
        for (const node of admitted) {
          // 同 NodeDialog：后端只在落盘那一刻补 id，而条目现在就需要稳定的实体寻址键。
          const entityId = node.id ? node.id : crypto.randomUUID();
          stage({
            id: `server:${entityId}`,
            kind: 'server',
            label: `${t('import.title')} ${node.name}`,
            entityPath: ['servers', entityId],
            nextValue: { ...node, id: entityId },
          });
        }
      } else {
        await api.server.addBulk(admitted);
        // 写后端即刷 store（同 NodeDialog/WgDialog/SubDialog/TsSettingsDialog）：`store.servers`
        // 只由 loadConfig/saveConfig 写。后端 `server_add_bulk` 确实发了 `broadcast_config_changed`、
        // `App.tsx:433` 也订阅着它兜底，但那是事件往返的**慢路径** —— 弹窗已经关掉、回执也已经
        // 弹出，节点网格却还空着。快路径与其余四个写节点的弹窗对齐，不在这里单开一种时序。
        await loadConfig(true);
      }
      // 回执。此前**只有**撞单例槽那一条腿会说话，而那条腿今天恒不命中（三个解析器都跳过
      // wireguard，见上方闸门注释）⇒ 实际形态是「导入完全静默」：弹窗一关，用户手上唯一的
      // 计数是刚刚消失的那颗按钮。
      // staged 与直落盘必须分开说：前者一个字节都没落盘，说「已导入」会让用户跳过条上的「保存」。
      // `rejected>0 && staged` 这一格今天不可达（闸门恒不命中），不为它再铺一对键；`endpoints[]`
      // 那条解析腿一旦接通，这里要连同上面的闸门一起改。
      if (rejected.length > 0) {
        toast.info(
          t('nodes.importSingletonSkipped', {
            count: admitted.length,
            skipped: rejected.length,
          })
        );
      } else {
        toast.success(
          staged
            ? t('nodes.importStagedOk', {
                count: admitted.length,
              })
            : t('nodes.importOk', { count: admitted.length })
        );
      }
      onAdded?.();
      closeImportDialog();
    } catch (e) {
      console.error('[ImportDialog] import failed:', e);
      toast.error(t('import.failed'));
    } finally {
      if (hasInstance(instanceId)) setImporting(false);
    }
  };

  const previewText = (): string => {
    switch (det.kind) {
      case 'links':
        return t('import.detLinks', { n: det.linkCount });
      case 'base64':
        return t('import.detBase64');
      case 'clash':
        return t('import.detClash');
      case 'subscription':
        return t('import.detSub');
      case 'unknown':
        return t('import.detUnknown');
      default:
        return '';
    }
  };

  return (
    <Modal
      titleId="add-dlg-title"
      title={t('import.title')}
      onClose={requestClose}
      closeDisabled={localImportCloseLocked(importing)}
      className="entry-form-dlg"
      icon={
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}>
          <path d="M12 15V4M8 8l4-4 4 4M4 15v3a2 2 0 002 2h12a2 2 0 002-2v-3" />
        </svg>
      }
      footer={
        <>
          <button type="button" className="btn ghost" onClick={requestClose} disabled={importing}>
            {t('common.cancel')}
          </button>
          <button
            type="button"
            className="btn flow"
            onClick={() => void (preview ? handleImport() : handleParse())}
            disabled={localImportPrimaryActionDisabled(parsing, importing)}
          >
            {parsing
              ? t('import.parsing')
              : importing
                ? t('import.importing')
              : preview
                ? t('import.submitN', {
                    count: preview.nodes.length,
                  })
                : t('import.parse')}
          </button>
        </>
      }
    >
      {/* 来源切换 */}
      <div className="fld">
        <label className="fld-l">{t('import.source')}</label>
        <div className="seg2" style={{ display: 'flex' }}>
          <button
            type="button"
            style={{ flex: 1 }}
            className={source === 'share' ? 'on' : ''}
            onClick={() => onSourceChange('share')}
            disabled={importing}
          >
            {t('import.pasteText')}
          </button>
          <button
            type="button"
            style={{ flex: 1 }}
            className={source === 'file' ? 'on' : ''}
            onClick={() => onSourceChange('file')}
            disabled={importing}
          >
            {t('import.localFile')}
          </button>
        </div>
      </div>

      {source === 'share' ? (
        <>
          <div className="fld">
            <label className="fld-l" htmlFor="share-input">
              {t('import.pasteLabel')}
            </label>
            <textarea
              id="share-input"
              className="input mono"
              rows={5}
              value={content}
              onChange={(e) => onContentChange(e.target.value)}
              placeholder={t('import.textPlaceholder')}
              disabled={importing}
            />
          </div>

          {det.kind !== 'empty' && (
            <div className="parse-list">
              <div className={`pl-row ${det.kind === 'unknown' ? 'parse-bad' : 'parse-ok'}`}>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}>
                  <path d="M5 12l5 5 9-11" />
                </svg>
                <span>{previewText()}</span>
              </div>
            </div>
          )}

          {det.kind === 'subscription' && (
            <div className="card-sub">
              {t('import.subHint')}{' '}
              <button
                type="button"
                className="btn ghost sm"
                onClick={() => open({ kind: 'sub' })}
              >
                {t('import.gotoSub')}
              </button>
            </div>
          )}

          <div className="card-sub">
            {t('import.landHint')}
          </div>
        </>
      ) : (
        <>
          <div
            className={`dz${dragOver ? ' drag' : ''}`}
            role="button"
            tabIndex={importing ? -1 : 0}
            aria-disabled={importing}
            onClick={() => {
              if (!importing) void pickFile();
            }}
            onKeyDown={(e) => {
              if (importing) return;
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                void pickFile();
              }
            }}
            onDragOver={(e) => {
              e.preventDefault();
              setDragOver(true);
            }}
            onDragLeave={() => setDragOver(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragOver(false);
              if (!importing) readFiles(e.dataTransfer.files);
            }}
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}>
              <path d="M12 15V4M8 8l4-4 4 4" />
              <path d="M4 15v3a2 2 0 002 2h12a2 2 0 002-2v-3" />
            </svg>
            <div>{t('import.dropHere')}</div>
            <div style={{ fontSize: 10.5, marginTop: 4 }}>.conf · .yaml · .json · .txt</div>
          </div>
          {fileHint && <div className="card-sub">{fileHint}</div>}
        </>
      )}

      {/* 解析结果预览。
       *
       * 文案全部取自**既有译文**（`parse` / `nodesTitle` / `unsupportedBadge` / `unsupportedTip` /
       * `skippedTitle` / `submitN {{count}}` / `resultUnsupported`，五语齐备）：这个预览阶段本来
       * 就在设计里，只是 Polaris 移植时没落地，整套躺在零消费点的 `localImport.*` 里。
       * 不另起一套新键：那等于把同一件事的文案写第二份，且要重新铺 5 个语种。 */}
      {preview && (
        <div className="imp-preview">
          <div className="imp-stats">
            <span className="imp-stat ok">
              {t('import.parsed', {
                nodes: preview.nodes.length,
                subs: preview.subscriptions.length,
              })}
            </span>
            {/* 三个「不是全都顺利」的计数**只在非零时出现** —— 恒显示会让「一切正常」和
                「丢了 4 个」在视觉上长得一样，用户扫一眼分不出来。 */}
            {preview.stats.unsupported > 0 && (
              <span className="imp-stat warn" data-tip={t('import.unsupportedTip')}>
                {t('import.resultUnsupported', {
                  count: preview.stats.unsupported,
                })}
              </span>
            )}
            {preview.stats.skipped + preview.stats.failed > 0 && (
              <span className="imp-stat bad">
                {t('import.skippedTitle', {
                  count: preview.stats.skipped + preview.stats.failed,
                })}
              </span>
            )}
          </div>

          {preview.warnings.length > 0 && (
            <ul className="imp-warn">
              {preview.warnings.map((w) => (
                <li key={w}>{w}</li>
              ))}
            </ul>
          )}

          <div className="card-sub" style={{ marginBottom: 5 }}>
            {t('import.nodesTitle')}
          </div>
          <ul className="imp-list">
            {preview.nodes.map((n, i) => (
              <li key={n.id || `${n.name}-${i}`}>
                <span className="imp-name" data-tip={n.name}>
                  {n.name}
                </span>
                {/* `unsupported` 的后端判据就是 `protocol === 'custom'`
                    （commands/subscription.rs 按此派生计数），故此处同判据、不另立一份。 */}
                {n.protocol === 'custom' ? (
                  <span className="imp-badge" data-tip={t('import.unsupportedTip')}>
                    {t('import.unsupportedBadge')}
                  </span>
                ) : (
                  <span className="imp-proto">{n.protocol}</span>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
    </Modal>
  );
}

export default ImportDialog;
