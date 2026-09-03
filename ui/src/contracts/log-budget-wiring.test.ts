/**
 * W26 跨文件接线门：行为预算在 Rust 单测，这里钉住最容易被后续“局部优化”拆开的四条生产腿。
 */
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

import { moduleSource, moduleSourceWithTests } from './rust-source.test-support';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../../');
const read = (path: string) => readFileSync(resolve(ROOT, path), 'utf8');

describe('W26 bounded core-log wiring', () => {
  it('runtime never hands a fixed output file back to sing-box', () => {
    // 两条断言的取材面**不同**，不能合成一坨：
    // - `log_file_path: None` 是生产接线 ⇒ 只看生产源码，免得哪天测试夹具里出现同形串把它喂饱；
    // - 那个 `#[test]` 名字是「行为预算真被测了」的凭据 ⇒ 必须看含 tests 的取材面（它现在住在
    //   `runtime/proxy/tests/`，写死 `runtime/proxy.rs` 会把它整个丢掉）。
    expect(moduleSource('src-tauri/src/runtime/proxy')).toContain('log_file_path: None');
    expect(moduleSourceWithTests('src-tauri/src/runtime/proxy')).toContain(
      'runtime_log_output_is_owned_by_bounded_sink_not_core',
    );
  });

  it('all three helper spawners drain pipes through the shared bounded writer', () => {
    // 这两支各带一条**否定**断言（`spawn_pipe_loggers(` 的无界老腿不得回潮），所以取的是
    // 模块生产面而不是写死 `<模块>.rs`：spawner 拆出生产子模块时，写死单文件的否定断言会
    // 静默恒真 —— 门还在、报告还是绿的，判据已经没了。`tests/` 必须剔除（夹具里的同形串会假红）。
    for (const module of [
      'crates/helper/src/platform/macos/server',
      'crates/helper/src/platform/windows/winproc/win',
    ]) {
      const source = moduleSource(module);
      expect(source, module).toContain('preopen_log_files');
      expect(source, module).toContain(
        'polaris_log_budget::spawn_pipe_loggers_with_preopened_files(',
      );
      expect(source, module).toContain('polaris_log_budget::spawn_pipe_drainers(');
      expect(source, module).not.toContain('polaris_log_budget::spawn_pipe_loggers(');
      expect(source, module).toContain('std::process::Stdio::piped()');
    }

    const linux = read('crates/helper/src/platform/linux/server.rs');
    expect(linux).toContain('polaris_log_budget::spawn_pipe_loggers_with_file(');
    expect(linux).toContain('std::process::Stdio::piped()');
    expect(linux).toContain('std::os::unix::fs::fchown(file, Some(uid), Some(gid))');

    const budget = read('crates/log-budget/src/lib.rs');
    expect(budget).toContain('after_open(writer.as_ref().map(|opened| &opened.file))');
  });

  it('legacy log is surfaced and only archived/deleted after an explicit user action', () => {
    const commands = read('src-tauri/src/commands/misc/logs.rs');
    const archive = commands.indexOf('fn archive_legacy_log(');
    const copy = commands.indexOf('std::fs::copy(source, &temporary)', archive);
    const sync = commands.indexOf('.and_then(|file| file.sync_all())', copy);
    const commit = commands.indexOf('std::fs::rename(&temporary, destination)', sync);
    const remove = commands.indexOf('std::fs::remove_file(source)', commit);
    expect([archive, copy, sync, commit, remove].every((position) => position >= 0)).toBe(true);
    expect(archive).toBeLessThan(copy);
    expect(copy).toBeLessThan(sync);
    expect(sync).toBeLessThan(commit);
    expect(commit).toBeLessThan(remove);

    const screen = read('ui/src/components/screens/logs/LogsScreen.tsx');
    expect(screen).toContain('.legacyInfo()');
    expect(screen).toContain('.archiveLegacy()');
    expect(screen).toContain('.deleteLegacy()');
    expect(screen).toContain("confirmTwice(DELETE_LEGACY_KEY");
    expect(screen).toContain("t('logs.legacyBody'");
    expect(screen).toContain("t('logs.archiveLegacy')");
    expect(screen).toContain("t('logs.deleteLegacy')");
    expect(commands).toContain('key::NATIVE_LOG_FILE_TYPE');

    const deleteCommand = commands.slice(
      commands.indexOf('pub fn logs_delete_legacy('),
      commands.indexOf('fn delete_legacy_log('),
    );
    expect(deleteCommand).toContain('state.config().dir().join(LEGACY_SINGBOX_LOG)');
    expect(deleteCommand).not.toMatch(/(?:path|source)\s*:\s*(?:String|PathBuf)/);
  });
});
