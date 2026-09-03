import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const read = (rel: string) =>
  readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'utf8');

describe('主内容页页头', () => {
  it('日志与规则资源只保留标题，不重新引入副标题消费点', () => {
    expect(read('./logs/LogsScreen.tsx')).not.toContain("t('logs.pageDesc')");
    expect(read('./resources/ResourcesScreen.tsx')).not.toContain("t('resources.sub')");
  });

  it('非设置页标题与右侧操作垂直居中，设置页继续使用独立基线布局', () => {
    const css = read('../../styles/index.css').replace(/\/\*[\s\S]*?\*\//g, '');
    expect(css).toMatch(
      /\.screen\s*>\s*\.phead:not\(\.settings-phead\)\s*\{[^}]*align-items\s*:\s*center/
    );
    expect(css).toMatch(
      /\.screen\s*>\s*\.phead:not\(\.settings-phead\)\s+\.acts\s+\.btn\s*\{[^}]*height\s*:\s*32px[^}]*padding-block\s*:\s*0/
    );
    expect(read('./settings/Primitives.tsx')).toContain('className="phead settings-phead"');
  });

  it('应用分流统计跟在标题同行，复用节点页标题结构且不保留独立摘要间距', () => {
    const appPolicy = read('./app-policy/AppPolicyScreen.tsx');
    const header = appPolicy.match(
      /<div className="phead">([\s\S]*?)<\/div>\s*\n\s*\{\/\* Windows-only/
    )?.[1];
    expect(header).toContain('<div className="ph-title">');
    expect(header).toContain("<h1>{t('sidebar.appPolicy')}</h1>");
    expect(header).toContain('<div className="app-summary">');
    expect(header).toContain('<div className="acts">');

    const css = read('../../styles/index.css').replace(/\/\*[\s\S]*?\*\//g, '');
    expect(css).toMatch(
      /#s-apppolicy\s*>\s*\.phead\s+\.app-summary\s*\{[^}]*margin-bottom\s*:\s*0/
    );
  });

  it('DNS 三工作区共用页头添加入口，Server / Group 添加编辑只走统一弹窗', () => {
    const rules = read('./rules/RulesScreen.tsx');
    const resources = read('./rules/DnsPolicyWorkspace.tsx');
    const host = read('../dialogs/DialogHost.tsx');

    expect(rules).toContain("openDialog({ kind: 'dns-server' })");
    expect(rules).toContain("openDialog({ kind: 'dns-group' })");
    expect(resources).toContain("openDialog({ kind: 'dns-server', serverId: server.id })");
    expect(resources).toContain("openDialog({ kind: 'dns-group', groupId: group.id })");
    expect(host).toContain("case 'dns-server':");
    expect(host).toContain("case 'dns-group':");
    expect(resources).not.toContain('dns-resource-editor');
    expect(resources).not.toMatch(/<details[^>]+dns-resource-card/);
  });

  it('DNS 与流量规则复用横向优先级流程，DNS 不保留运行设置 Tab 或纵向冗余标题', () => {
    const rules = read('./rules/RulesScreen.tsx');
    const geo = read('./rules/GeoCard.tsx');
    expect(rules).toContain('<PriorityFlow');
    expect(rules).toContain("label={t('rules.dnsWorkspace.priority')}");
    expect(rules).toContain("t('rules.dnsWorkspace.systemStage')");
    expect(rules).toContain("t('rules.chainCustom')");
    expect(rules).toContain("t('rules.chainDefault')");
    expect(rules).not.toContain('runtimeTab');
    expect(rules).not.toContain('dnsPriority');
    expect(geo).toContain('<PriorityFlow');
  });

  it('DNS 规则主体按系统保护、自定义、默认排列，两个内置阶段有一致标识', () => {
    const rules = read('./rules/RulesScreen.tsx');
    const workspace = read('./rules/DnsPolicyWorkspace.tsx');
    const priority = rules.indexOf('className="dns-priority-flow"');
    const system = rules.indexOf('className="dns-system-rules"');
    const custom = rules.indexOf('<div id="rules-body">');
    const fallback = rules.indexOf('<DnsPolicyWorkspace view="rules" />');
    expect(system).toBeGreaterThan(priority);
    expect(custom).toBeGreaterThan(system);
    expect(fallback).toBeGreaterThan(custom);
    expect(rules).toContain('<Fold');
    expect(rules).toContain("t('settings.dns.builtinTag')");
    expect(workspace).toContain("t('settings.dns.builtinTag')");
    expect(rules).not.toContain('<details className="card dns-system-rules"');
  });

  it('DNS 优先级框与后续规则阶段保留清晰间距', () => {
    const css = read('../../styles/screens.css').replace(/\/\*[\s\S]*?\*\//g, '');
    expect(css).toMatch(/\.dns-priority-flow\s*\{[^}]*margin\s*:\s*0 0 20px/);
    expect(css).toMatch(/\.dns-system-rules\s*\{[^}]*margin\s*:\s*0 0 20px/);
    expect(css).toMatch(/\.policy-default-policy\s*\{[^}]*margin\s*:\s*20px 0 0/);
  });

  it('导入节点首次点击直接打开粘贴文本弹窗，不在挂载时读取剪贴板', () => {
    const header = read('./nodes/NodesHeader.tsx');
    const dialog = read('../dialogs/ImportDialog.tsx');

    expect(header).toContain("openDialog({ kind: 'import', onAdded: () => setActiveTab('manual') })");
    expect(dialog).toContain("useState<Source>('share')");
    expect(dialog).toContain("t('import.pasteText')");
    expect(dialog).not.toContain('navigator.clipboard.readText()');
  });
});
