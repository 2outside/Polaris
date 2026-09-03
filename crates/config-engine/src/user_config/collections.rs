//! 集合工具（上游 `shared/collections.ts` 1:1 移植）。纯函数。

#![forbid(unsafe_code)]

/// 去重保序：按首次出现顺序返回去重后的数组（= JS `Array.from(new Set(items))`）。
/// 上游 `dedupe`。
pub fn dedupe<T: Clone + Eq + std::hash::Hash>(items: impl IntoIterator<Item = T>) -> Vec<T> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for item in items {
        if seen.insert(item.clone()) {
            out.push(item);
        }
    }
    out
}

/// 字符串去重 + 修剪空白 + 丢弃空串（dedupe 的 trim + filter(Boolean) 变体），保序。
/// 上游 `dedupeTrim`。
pub fn dedupe_trim(list: impl IntoIterator<Item = String>) -> Vec<String> {
    let trimmed: Vec<String> = list
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    dedupe(trimmed)
}

#[cfg(test)]
mod tests;
