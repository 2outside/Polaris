/**
 * 用户可见失败面不得直出 IPC 的 `Error.message`/回包诊断。
 *
 * 这是一组源码契约：vitest 的 node 环境不能完整挂载 Tauri dialog/tray，故锁住每个已经取证的
 * DOM、toast 与托盘 notice 边界。诊断必须先 `console.error`，用户只得到已有的五语文案或稳定码映射。
 */
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

function source(relative: string): string {
  return readFileSync(fileURLToPath(new URL(relative, import.meta.url)), 'utf8');
}

const SUB_DIALOG = source('../components/dialogs/SubDialog.tsx');
const IMPORT_DIALOG = source('../components/dialogs/ImportDialog.tsx');
const RES_CATALOG = source('../components/dialogs/ResCatalogDialog.tsx');
const NODE_DIALOG = source('../components/dialogs/NodeDialog.tsx');
const GENERAL = source('../components/screens/settings/SettingsGeneral.tsx');
const CORE_BANNER = source('../components/screens/settings/CoreVersionBanner.tsx');
const CONNECTIONS = source('../components/screens/connections/ConnectionsScreen.tsx');
const TRAY = source('../tray/TrayMenu.tsx');
const PROXY_ERROR_TEXT = source('../domain/proxy-error-text.ts');
const APP_STORE = source('../store/app-store.ts');
const APP_PRESETS_STORE = source('../store/use-app-presets-store.ts');
const PROCESS_PICKER = source('../components/dialogs/ProcPickDialog.tsx');

describe('用户可见 IPC 失败面', () => {
  it('订阅预检、文件选择、密码保存都本地化，原始诊断只写日志', () => {
    expect(SUB_DIALOG).toContain("console.error('[SubDialog] preview failed:', e)");
    expect(SUB_DIALOG).toContain("setPreviewMsg({ ok: false, text: t('sub.previewFail') })");
    expect(IMPORT_DIALOG).toContain("console.error('[ImportDialog] pick file failed:', e)");
    expect(IMPORT_DIALOG).toContain("setFileHint(t('import.fileReadFail'))");
    expect(GENERAL).toContain("console.error('[SettingsGeneral] save privacy password failed:', e)");
    expect(GENERAL).toContain("setPwErr(t('common.saveFailed'))");
  });

  it('资源目录以稳定码保存持久错误，换核只显示既有短提示', () => {
    expect(RES_CATALOG).toContain("type CatalogLoadError = 'RESOURCE_CATALOG_LOAD_FAILED'");
    expect(RES_CATALOG).toContain("setLoadErr(catalogLoadFailure('initial', e))");
    expect(RES_CATALOG).toContain("setExtErr(catalogLoadFailure('external', e))");
    expect(RES_CATALOG).toContain("t('errors.operationFailed')");
    expect(CORE_BANNER).toContain("console.error('[CoreVersionBanner] manual core replacement failed:', r.error)");
    expect(CORE_BANNER).toContain("setReplaceErr(t('settings.core.swapFailedShort'))");
    expect(CORE_BANNER).not.toMatch(/setReplaceErr\(e instanceof Error \? e\.message/);
  });

  it('连接关闭、节点 IPC 失败与托盘 notice 不透传 Error.message', () => {
    expect(CONNECTIONS).toContain('const rollback = () => {');
    expect(CONNECTIONS).toContain('toast.error(closeFailedText);');
    expect(CONNECTIONS).not.toContain('rollback(err instanceof Error ? err.message');
    expect(NODE_DIALOG).toContain("console.error('[NodeDialog] custom outbound probe failed:', e)");
    expect(NODE_DIALOG).toContain("r.errorPath ?? 'unclassified'");
    expect(NODE_DIALOG).not.toContain("custom outbound compatibility rejected:', r");
    expect(NODE_DIALOG).toContain("t('node.customProbe.unsupportedWithPath'");
    expect(NODE_DIALOG).not.toContain('probeResult.raw');
    expect(NODE_DIALOG).toContain("console.error('[NodeDialog] save failed:', e)");
    expect(TRAY).toContain("detail: t('tray.actionFailedDetail')");
    // `?? ''` 后再下否定断言 = 恒真（切片塌成空串照样绿）。按同文件姊妹腿（proxyErrorReason）
    // 的形态先下存在性守卫：搬进嵌套作用域、改成 `function` 声明、右界缩进变化都会转红而非静默放行。
    // 右界不再写死两格缩进（`\n  };`），改成「任意缩进的一行 `};`」，重新缩进不再是假失配。
    const notice = TRAY.match(/const noticeActionFailure[\s\S]*?\n +};/)?.[0];
    expect(notice, 'noticeActionFailure 未找到，门已失去判据').toBeTruthy();
    expect(notice).not.toContain('.message');
  });

  it('代理错误解析器不读取 wire message', () => {
    const resolver = PROXY_ERROR_TEXT.match(
      /export function proxyErrorReason[\s\S]*?\n}/
    )?.[0];
    expect(resolver, '解析器函数未找到，门已失去判据').toBeTruthy();
    expect(resolver).not.toContain('.message');
    expect(resolver).not.toMatch(/return\s+message\b/);
  });

  it('配置、预设与进程枚举只保存可渲染的语义状态', () => {
    expect(APP_STORE).not.toContain('configError:');
    expect(APP_PRESETS_STORE).toContain('failed: boolean;');
    expect(APP_PRESETS_STORE).not.toMatch(/error:\s*string\s*\|\s*null/);
    expect(PROCESS_PICKER).toContain("| { phase: 'error' };");
    expect(PROCESS_PICKER).not.toMatch(/phase:\s*'error';\s*message:/);
  });
});
