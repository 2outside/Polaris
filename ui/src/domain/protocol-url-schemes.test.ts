import { describe, expect, it } from 'vitest';
import { isSupportedShareUrl, SUPPORTED_URL_SCHEMES } from './protocol-url-schemes';

describe('isSupportedShareUrl', () => {
  /** 前缀精确匹配：'http' 不得误命中 'https://'，故白名单顺序无关。 */
  it('按 `<scheme>://` 前缀精确匹配', () => {
    expect(isSupportedShareUrl('http://a.example.com:8080')).toBe(true);
    expect(isSupportedShareUrl('https://a.example.com')).toBe(true);
    expect(isSupportedShareUrl('naive+https://u:p@a.example.com')).toBe(true);
    expect(isSupportedShareUrl('ftp://a.example.com')).toBe(false);
    expect(isSupportedShareUrl('a.example.com')).toBe(false);
  });

  /**
   * 🔴 **scheme 大小写不敏感**（RFC 3986 §3.1；变异锁：改回 `url.startsWith(...)` → 本条转红）。
   *
   * 与 Rust 侧 `share_link::is_supported_share_url` 同口径。后端放宽而这里仍大小写敏感的话，
   * 用户粘贴的 `HTTP://…` 会在导入对话框里被前端先行滤掉（ImportDialog 用本函数筛行），
   * issue #191 那类「前后端判定分裂」原样复发——这正是 issue #1 里 HTTP 节点「识别不出」的一种形态。
   */
  it('scheme 大小写不敏感', () => {
    for (const url of [
      'HTTP://a.example.com:8080',
      'Http://a.example.com:8080',
      'HTTPS://a.example.com',
      'VLESS://a.example.com',
      'Socks5://a.example.com:1080',
    ]) {
      expect(isSupportedShareUrl(url)).toBe(true);
    }
    // 放宽的只是大小写，不是白名单本身。
    expect(isSupportedShareUrl('FTP://a.example.com')).toBe(false);
  });

  /** 白名单每一条都得能被自己的链接命中（漏抄/错抄一条即红）。 */
  it('白名单每条 scheme 都可用', () => {
    for (const scheme of SUPPORTED_URL_SCHEMES) {
      expect(isSupportedShareUrl(`${scheme}://u:p@a.example.com:443#n`)).toBe(true);
      expect(isSupportedShareUrl(`${scheme.toUpperCase()}://u:p@a.example.com:443#n`)).toBe(true);
    }
  });
});
