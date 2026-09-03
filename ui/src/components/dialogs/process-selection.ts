/**
 * 进程名输入与进程选择器共享的规范化入口。
 *
 * 保留首个值的原始大小写与顺序，仅用大小写不敏感键去重。这样既不会在打开选择器时
 * 改写用户手填内容，也能让 Windows 上仅大小写不同的同名进程保持单一规则项。
 */
export function normalizeProcessNames(values: Iterable<string>): string[] {
  const result: string[] = [];
  const seen = new Set<string>();
  for (const raw of values) {
    const value = raw.trim();
    if (!value) continue;
    const key = processNameKey(value);
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(value);
  }
  return result;
}

export function processNameKey(value: string): string {
  return value.trim().toLowerCase();
}

export function parseProcessNames(value: string): string[] {
  return normalizeProcessNames(value.split(/[,\n]/));
}
