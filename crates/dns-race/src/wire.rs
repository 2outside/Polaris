//! 极小 DNS wire（application/dns-message, RFC 1035）编解码 —— 上游 `shared/dns-wire.ts` 1:1 移植。
//!
//! **纯函数、零 I/O、可逐字节单测**：本模块是整条竞速链上唯一「判定谁赢」的依据来源
//! （[`classify_dns_response`] 的三态直接决定抢跑/等待/递减），故与网络彻底隔离。
//!
//! 移植口径（与 TS 版逐条对应）：
//! - TS 侧 `DataView.getUint16` 越界会抛 `RangeError`，被外层 `try/catch` 兜成「FAIL / 空 / null」。
//!   Rust 侧无异常：统一用返回 [`Option`] 的 `u16_at` / `skip_name`，在各入口用 `?` 汇到同一个
//!   保守兜底值（`FAIL` / `[]` / `None`）——语义等价，且不可能漏掉一条越界腿。
//! - 只需要 A / AAAA 两种 rdata 的原始字节（decoy 匹配），其余记录一律跳过、不解释。

#![forbid(unsafe_code)]

/// A 记录类型码。
pub const TYPE_A: u16 = 1;
/// AAAA 记录类型码。
pub const TYPE_AAAA: u16 = 28;
/// IN class（与 上游 `decodeDnsAnswers` 同口径：只认 class=IN）。
const CLASS_IN: u16 = 1;

const RCODE_NOERROR: u16 = 0;
const RCODE_SERVFAIL: u16 = 2;
const RCODE_NXDOMAIN: u16 = 3;

/// 大端读 u16。越界 → `None`（等价 TS 侧 `getUint16` 抛 `RangeError`）。
fn u16_at(buf: &[u8], off: usize) -> Option<u16> {
    let hi = *buf.get(off)? as u16;
    let lo = *buf.get(off + 1)? as u16;
    Some((hi << 8) | lo)
}

/// 大端写 u16（`out` 必须已有 `off+2` 字节；调用方保证）。
fn put_u16(out: &mut [u8], off: usize, v: u16) {
    out[off] = (v >> 8) as u8;
    out[off + 1] = (v & 0xff) as u8;
}

/// 跳过 QNAME / NAME 的标签序列与压缩指针（`0xC0`），返回名字之后的偏移。
///
/// 越界 / 畸形（无 root、自指指针等）→ `None`。循环上限 = `buf.len()`，杜绝构造畸形包导致死循环
/// （上游 `skipName` 的 `guard` 同义）。
fn skip_name(buf: &[u8], offset: usize) -> Option<usize> {
    let mut off = offset;
    for _ in 0..=buf.len() {
        let len = *buf.get(off)?;
        if len == 0 {
            return Some(off + 1); // root，名字结束
        }
        if len & 0xc0 == 0xc0 {
            return Some(off + 2); // 压缩指针占 2 字节，名字到此结束
        }
        off += 1 + len as usize;
    }
    None
}

/// DNS query 的首个 question。上游 `DnsQuestion`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    /// message id（响应必须回填同一 id，否则内核丢弃）。
    pub id: u16,
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// 解析 DNS query 首个 question。畸形 / 无 question / 越界 → `None`（调用方按 FAIL/SERVFAIL 处理）。
///
/// query 一般无压缩指针，遇到即防御性停止 qname 解析（与 上游 同）。
#[must_use]
pub fn decode_dns_question(wire: &[u8]) -> Option<DnsQuestion> {
    if wire.len() < 12 {
        return None;
    }
    let id = u16_at(wire, 0)?;
    if u16_at(wire, 4)? < 1 {
        return None; // QDCOUNT < 1
    }
    let mut off = 12usize;
    let mut labels: Vec<String> = Vec::new();
    for _ in 0..=wire.len() {
        let &len = wire.get(off)?;
        if len == 0 {
            off += 1;
            break;
        }
        if len & 0xc0 == 0xc0 {
            off += 2; // 压缩指针（query 罕见）：防御性停止 qname 解析
            break;
        }
        off += 1;
        let end = off + len as usize;
        if end > wire.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&wire[off..end]).into_owned());
        off = end;
    }
    Some(DnsQuestion {
        id,
        qname: labels.join("."),
        qtype: u16_at(wire, off)?,
        qclass: u16_at(wire, off + 2)?,
    })
}

/// 响应三态。上游 `DnsResponseClass`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsResponseClass {
    /// NOERROR 且 answer 含请求 qtype 的记录（含 CNAME 链末端的目标记录）。
    Hit,
    /// NOERROR 但无该 qtype 记录（NODATA），或 NXDOMAIN —— 「正常空解析」。
    Empty,
    /// SERVFAIL/REFUSED 等 / QR=0 非响应 / TC=1 截断 / 畸形 —— 「上游故障」。
    Fail,
}

/// 三态分类（issue #147 §4）。供竞速聚合：HIT 抢跑、EMPTY 不抢跑（等本层全 settle 才下空结论）、
/// 全 FAIL → SERVFAIL。**FAIL ≠ EMPTY 是本功能的核心区分**：把上游故障当「域名无记录」会让节点
/// 直接判死，而不是让干净上游兜住。
#[must_use]
pub fn classify_dns_response(resp: &[u8], qtype: u16) -> DnsResponseClass {
    classify_inner(resp, qtype).unwrap_or(DnsResponseClass::Fail)
}

/// 内层：任一越界/畸形 → `None` → 外层兜 FAIL（等价 TS 的 `catch { return 'FAIL' }`）。
fn classify_inner(resp: &[u8], qtype: u16) -> Option<DnsResponseClass> {
    if resp.len() < 12 {
        return Some(DnsResponseClass::Fail);
    }
    let flags = u16_at(resp, 2)?;
    if flags & 0x8000 == 0 {
        return Some(DnsResponseClass::Fail); // QR=0：非响应
    }
    if flags & 0x0200 != 0 {
        // TC=1 截断（仅 UDP 上游可达）：当上游故障，不把部分 A 当权威转发，让他者/SERVFAIL 兜。
        return Some(DnsResponseClass::Fail);
    }
    let rcode = flags & 0x000f;
    if rcode == RCODE_NXDOMAIN {
        return Some(DnsResponseClass::Empty);
    }
    if rcode != RCODE_NOERROR {
        return Some(DnsResponseClass::Fail); // SERVFAIL/REFUSED/…
    }
    let qd = u16_at(resp, 4)?;
    let an = u16_at(resp, 6)?;
    let mut off = 12usize;
    for _ in 0..qd {
        off = skip_name(resp, off)? + 4;
    }
    for _ in 0..an {
        off = skip_name(resp, off)?;
        if off + 10 > resp.len() {
            return Some(DnsResponseClass::Fail);
        }
        let rtype = u16_at(resp, off)?;
        let klass = u16_at(resp, off + 2)?;
        let rdlength = u16_at(resp, off + 8)?;
        if rtype == qtype && klass == CLASS_IN {
            return Some(DnsResponseClass::Hit);
        }
        off = off + 10 + rdlength as usize;
        if off > resp.len() {
            return Some(DnsResponseClass::Fail);
        }
    }
    Some(DnsResponseClass::Empty) // NOERROR 无该 qtype 记录（NODATA）
}

/// 从 DNS 响应抽出全部 A(4B)/AAAA(16B) 记录的 rdata **原始网络字节**（供 decoy 段匹配）。
/// 任何异常 / 截断 / RCODE!=0 → `[]`。按报文出现顺序返回。上游 `extractAnswerIpBytes`。
#[must_use]
pub fn extract_answer_ip_bytes(resp: &[u8]) -> Vec<Vec<u8>> {
    extract_inner(resp).unwrap_or_default()
}

fn extract_inner(resp: &[u8]) -> Option<Vec<Vec<u8>>> {
    if resp.len() < 12 {
        return Some(Vec::new());
    }
    if u16_at(resp, 2)? & 0x000f != 0 {
        return Some(Vec::new()); // RCODE != 0
    }
    let qd = u16_at(resp, 4)?;
    let an = u16_at(resp, 6)?;
    let mut off = 12usize;
    for _ in 0..qd {
        off = skip_name(resp, off)? + 4;
    }
    let mut ips: Vec<Vec<u8>> = Vec::new();
    for _ in 0..an {
        off = skip_name(resp, off)?;
        if off + 10 > resp.len() {
            return None;
        }
        let rtype = u16_at(resp, off)?;
        let klass = u16_at(resp, off + 2)?;
        let rdlength = u16_at(resp, off + 8)? as usize;
        let rdata = off + 10;
        if rdata + rdlength > resp.len() {
            return None;
        }
        if klass == CLASS_IN
            && ((rtype == TYPE_A && rdlength == 4) || (rtype == TYPE_AAAA && rdlength == 16))
        {
            ips.push(resp[rdata..rdata + rdlength].to_vec());
        }
        off = rdata + rdlength;
    }
    Some(ips)
}

/// 回填 DNS message id（响应 id 必须 == query id，否则内核丢弃）。返回副本，不改入参。
/// 长度 <2 的畸形包原样返回（无处可写）。上游 `setDnsMessageId`。
#[must_use]
pub fn set_dns_message_id(wire: &[u8], id: u16) -> Vec<u8> {
    let mut out = wire.to_vec();
    if out.len() >= 2 {
        put_u16(&mut out, 0, id);
    }
    out
}

/// 构造 SERVFAIL 响应（全上游 FAIL 时回内核，区别于「域名无记录」的 EMPTY）。
///
/// 截到首 question 末（丢弃 query 的 OPT/additional），置 QR=1 RA=1 RCODE=2、清 AN/NS/AR。
/// 固定 ≥12 字节 header（畸形/截断 query 不足时补 0），防越界。上游 `buildServfail`。
#[must_use]
pub fn build_servfail(query: &[u8]) -> Vec<u8> {
    // question 「完整」的判据 = qname 可跳完 **且** 其后的 qtype(2)+qclass(2) 也整个在包内。
    // 只看截断后的 `end >= 16` 会误报：`12B header + 01 61 00 + 2B` 这种「qname 完整但 qtype/qclass
    // 被截」的 query，end 被 clamp 到 17（≥16）→ 产出 QDCOUNT=1 却只带半个 question 的畸形 SERVFAIL，
    // 内核直接丢弃 ⟹ fail-open 退化成超时（比如实回 SERVFAIL 更糟：内核要等满超时才换腿）。
    let full_end = skip_name(query, 12).map(|n| n + 4); // qname + qtype(2) + qclass(2)
    let question_complete = full_end.is_some_and(|e| e <= query.len());
    let mut end = full_end.unwrap_or_else(|| query.len().min(12));
    if end > query.len() {
        end = query.len();
    }
    let want = end.max(12);
    let mut out = vec![0u8; want];
    let copy = query.len().min(want);
    out[..copy].copy_from_slice(&query[..copy]);
    let req_flags = u16_at(&out, 2).unwrap_or(0);
    // QR=1 | Opcode(保留=0) | RD(echo from query) | RA=1 | RCODE=SERVFAIL
    put_u16(
        &mut out,
        2,
        0x8000 | (req_flags & 0x0100) | 0x0080 | RCODE_SERVFAIL,
    );
    put_u16(&mut out, 4, u16::from(question_complete)); // QDCOUNT：question 完整才 1，否则 0
    put_u16(&mut out, 6, 0); // ANCOUNT
    put_u16(&mut out, 8, 0); // NSCOUNT
    put_u16(&mut out, 10, 0); // ARCOUNT
    out
}

/// 一条待编码的 answer 记录（仅 `system` 上游用）。上游 `buildAnswerResponse` 的 `answers` 元素。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnswerRecord {
    pub rtype: u16,
    pub rdata: Vec<u8>,
}

/// 构造 NOERROR 响应（system/本地解析得到的 IP → wire）：echo question + A/AAAA answers
/// （name 用压缩指针 `0xC00C` 指向 question 的 qname）。空 answers → NODATA（EMPTY）。畸形 query → SERVFAIL。
///
/// **仅 `system` 上游用**：DoH/UDP 上游直接透传上游原始响应，不经此（保住多 A/TTL/CNAME 全量供内核
/// DialSerial 逐 IP 重试）。上游 `buildAnswerResponse`。
#[must_use]
pub fn build_answer_response(query: &[u8], answers: &[AnswerRecord]) -> Vec<u8> {
    if query.len() < 12 {
        return build_servfail(query);
    }
    let Some(q_end) = skip_name(query, 12).map(|n| n + 4) else {
        return build_servfail(query);
    };
    if q_end > query.len() {
        return build_servfail(query);
    }
    let mut out: Vec<u8> = query[..q_end].to_vec();
    for a in answers {
        out.extend_from_slice(&[0xc0, 0x0c]); // name: 指向 offset 12（question qname）
        out.extend_from_slice(&a.rtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]); // ttl 60
        let rdlen = u16::try_from(a.rdata.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&rdlen.to_be_bytes());
        out.extend_from_slice(&a.rdata);
    }
    let req_flags = u16_at(&out, 2).unwrap_or(0);
    put_u16(&mut out, 2, 0x8000 | (req_flags & 0x0100) | 0x0080); // QR=1 RD(echo) RA=1 RCODE=0
                                                                  // QDCOUNT 必须重置为 1：out 是 query 前缀的副本，QDCOUNT 原样继承自 query，而我们**只回声了首个
                                                                  // question**（`skip_name(12)` 只跳一个名字）。QDCOUNT>1 的 query 若照抄计数 → 响应声称 N 个
                                                                  // question 却只带 1 个 → 内核解析越界判畸形丢弃。
    put_u16(&mut out, 4, 1); // QDCOUNT（只回声首 question）
    put_u16(
        &mut out,
        6,
        u16::try_from(answers.len()).unwrap_or(u16::MAX),
    ); // ANCOUNT
    put_u16(&mut out, 8, 0);
    put_u16(&mut out, 10, 0);
    out
}

/// 组装 A/AAAA 查询包（**仅单测构造样本用**：生产侧 query 由内核发来，本 crate 只转发不构造）。
/// 固定 header（RD=1，QDCOUNT=1）+ QNAME + QTYPE + QCLASS=IN。上游 `encodeDnsQuery`。
#[must_use]
pub fn encode_dns_query(domain: &str, qtype: u16, id: u16) -> Vec<u8> {
    let mut out = vec![0u8; 12];
    put_u16(&mut out, 0, id);
    put_u16(&mut out, 2, 0x0100); // QR=0 Opcode=0 RD=1
    put_u16(&mut out, 4, 1); // QDCOUNT
    for label in domain.trim_end_matches('.').split('.') {
        let b = label.as_bytes();
        out.push(u8::try_from(b.len()).unwrap_or(u8::MAX));
        out.extend_from_slice(b);
    }
    out.push(0); // root label
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out
}

#[cfg(test)]
mod tests;
