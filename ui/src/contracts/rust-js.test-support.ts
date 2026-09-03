/** Rust 生产源码内嵌 JavaScript 的词法取材器；跨语言契约测试共用，避免各抄一份正则。 */

/**
 * 把 Rust 注释/字符串/字符字面量掩成空格并保留换行与字节位置。用于从生产语法面切函数、解析
 * attribute/宏注册；文档里的伪代码与注入脚本正文不会再喂绿 Rust 结构断言。
 */
export function rustCode(src: string): string {
  // `String#split('')` 保留 UTF-16 code-unit 索引；`[...src]` 会把 emoji 合成一个元素，导致后续
  // brace 切片的位置与原串错位（Rust 注释里确有 emoji）。
  const out = src.split('');
  const mask = (start: number, end: number): void => {
    for (let at = start; at < end; at++) if (out[at] !== '\n' && out[at] !== '\r') out[at] = ' ';
  };
  let i = 0;
  while (i < src.length) {
    if (src.startsWith('//', i)) {
      const end = src.indexOf('\n', i + 2);
      const stop = end < 0 ? src.length : end;
      mask(i, stop);
      i = stop;
      continue;
    }
    if (src.startsWith('/*', i)) {
      const start = i;
      let depth = 1;
      i += 2;
      while (i < src.length && depth > 0) {
        if (src.startsWith('/*', i)) {
          depth++;
          i += 2;
        } else if (src.startsWith('*/', i)) {
          depth--;
          i += 2;
        } else i++;
      }
      if (depth !== 0) throw new Error('[rust-js]:unterminated-block-comment');
      mask(start, i);
      continue;
    }
    const raw = src.slice(i).match(/^(?:b)?r(#+)?"/);
    if (raw) {
      const start = i;
      const hashes = raw[1] ?? '';
      const close = `"${hashes}`;
      const end = src.indexOf(close, i + raw[0].length);
      if (end < 0) throw new Error('[rust-js]:unterminated-raw-string');
      i = end + close.length;
      mask(start, i);
      continue;
    }
    const quoteAt = src[i] === '"' ? i : src[i] === 'b' && src[i + 1] === '"' ? i + 1 : -1;
    if (quoteAt >= 0) {
      const start = i;
      i = quoteAt + 1;
      let escaped = false;
      while (i < src.length) {
        const ch = src[i++];
        if (escaped) escaped = false;
        else if (ch === '\\') escaped = true;
        else if (ch === '"') break;
      }
      if (src[i - 1] !== '"') throw new Error('[rust-js]:unterminated-string');
      mask(start, i);
      continue;
    }
    // 只把确定的 char literal 掩掉；`'a` lifetime 没有尾引号，必须保留在代码态。
    if (src[i] === "'") {
      const char = src.slice(i).match(/^'(?:\\.|[^\\'\n])'/);
      if (char) {
        mask(i, i + char[0].length);
        i += char[0].length;
        continue;
      }
    }
    i++;
  }
  return out.join('');
}

/**
 * 只抽 Rust 源码里的字符串字面量：跳过注释/字符字面量，支持普通字符串与任意
 * `r###"…"###`。返回未反转义的字面量正文；本仓注入脚本使用 raw string，通道/全局名不受影响。
 */
export function rustStringLiterals(src: string): string[] {
  const out: string[] = [];
  let i = 0;
  while (i < src.length) {
    if (src.startsWith('//', i)) {
      i = src.indexOf('\n', i + 2);
      if (i < 0) break;
      continue;
    }
    if (src.startsWith('/*', i)) {
      const end = src.indexOf('*/', i + 2);
      if (end < 0) throw new Error('[rust-js]:unterminated-block-comment');
      i = end + 2;
      continue;
    }
    if (src[i] === "'") {
      i++;
      let escaped = false;
      while (i < src.length) {
        const ch = src[i++];
        if (escaped) escaped = false;
        else if (ch === '\\') escaped = true;
        else if (ch === "'" || ch === '\n') break;
      }
      continue;
    }
    const raw = src.slice(i).match(/^r(#+)?"/);
    if (raw) {
      const hashes = raw[1] ?? '';
      const start = i + raw[0].length;
      const close = `"${hashes}`;
      const end = src.indexOf(close, start);
      if (end < 0) throw new Error('[rust-js]:unterminated-raw-string');
      out.push(src.slice(start, end));
      i = end + close.length;
      continue;
    }
    if (src[i] === '"') {
      const start = ++i;
      let escaped = false;
      while (i < src.length) {
        const ch = src[i];
        if (escaped) escaped = false;
        else if (ch === '\\') escaped = true;
        else if (ch === '"') break;
        i++;
      }
      if (i >= src.length) throw new Error('[rust-js]:unterminated-string');
      out.push(src.slice(start, i));
      i++;
      continue;
    }
    i++;
  }
  return out;
}

/** Rust 字符串中的 Tauri raw-JS invoke：支持直接调用与同一脚本内的局部别名。 */
export function rawRustJsInvokes(src: string): string[] {
  const out: string[] = [];
  for (const literal of rustStringLiterals(src)) {
    const receivers = new Set(['(?:window\\.)?__TAURI_INTERNALS__']);
    const aliases = literal.matchAll(
      /\b(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:window\.)?__TAURI_INTERNALS__\s*;/g,
    );
    for (const match of aliases) receivers.add(match[1].replace(/[$]/g, '\\$&'));
    const invoke = new RegExp(
      `(?:${[...receivers].join('|')})\\.invoke\\s*\\(\\s*['"]([^'"]+)['"]`,
      'g',
    );
    let match: RegExpExecArray | null;
    while ((match = invoke.exec(literal))) out.push(match[1]);
  }
  return out;
}
