use super::*;

/// 构造一条 A 响应：query 回声 + n 条 A 记录（rdata 由入参给）。
fn a_response(query: &[u8], ips: &[[u8; 4]]) -> Vec<u8> {
    let answers: Vec<AnswerRecord> = ips
        .iter()
        .map(|ip| AnswerRecord {
            rtype: TYPE_A,
            rdata: ip.to_vec(),
        })
        .collect();
    build_answer_response(query, &answers)
}

#[test]
fn question_roundtrip() {
    let q = encode_dns_query("node.example.com", TYPE_A, 0x1234);
    let d = decode_dns_question(&q).expect("可解");
    assert_eq!(d.id, 0x1234);
    assert_eq!(d.qname, "node.example.com");
    assert_eq!(d.qtype, TYPE_A);
    assert_eq!(d.qclass, CLASS_IN);
}

#[test]
fn question_rejects_truncated_and_qdcount_zero() {
    assert!(decode_dns_question(&[]).is_none());
    assert!(decode_dns_question(&[0u8; 11]).is_none());
    let mut q = encode_dns_query("a.com", TYPE_A, 1);
    put_u16(&mut q, 4, 0); // QDCOUNT=0
    assert!(decode_dns_question(&q).is_none());
}

#[test]
fn classify_hit_empty_fail() {
    let q = encode_dns_query("a.com", TYPE_A, 7);
    // HIT：含请求 qtype 的记录。
    let hit = a_response(&q, &[[1, 2, 3, 4]]);
    assert_eq!(classify_dns_response(&hit, TYPE_A), DnsResponseClass::Hit);
    // EMPTY：NOERROR 无记录（NODATA）。
    let empty = a_response(&q, &[]);
    assert_eq!(
        classify_dns_response(&empty, TYPE_A),
        DnsResponseClass::Empty
    );
    // EMPTY：NXDOMAIN。
    let mut nx = empty.clone();
    put_u16(&mut nx, 2, 0x8180 | RCODE_NXDOMAIN);
    assert_eq!(classify_dns_response(&nx, TYPE_A), DnsResponseClass::Empty);
    // FAIL：SERVFAIL。
    let sf = build_servfail(&q);
    assert_eq!(classify_dns_response(&sf, TYPE_A), DnsResponseClass::Fail);
    // FAIL：QR=0（非响应）。
    assert_eq!(classify_dns_response(&q, TYPE_A), DnsResponseClass::Fail);
    // FAIL：畸形/截断。
    assert_eq!(
        classify_dns_response(&hit[..6], TYPE_A),
        DnsResponseClass::Fail
    );
}

#[test]
fn classify_truncated_bit_is_fail_not_hit() {
    // TC=1：即便带 A 记录也判 FAIL（不把部分答案当权威转发）。
    let q = encode_dns_query("a.com", TYPE_A, 7);
    let mut tc = a_response(&q, &[[1, 2, 3, 4]]);
    let flags = u16_at(&tc, 2).unwrap();
    put_u16(&mut tc, 2, flags | 0x0200);
    assert_eq!(classify_dns_response(&tc, TYPE_A), DnsResponseClass::Fail);
}

#[test]
fn classify_a_answer_is_empty_for_aaaa_query() {
    // 只有 A 记录、问的是 AAAA → NODATA（EMPTY），不是 HIT。
    let q = encode_dns_query("a.com", TYPE_AAAA, 9);
    let resp = a_response(&q, &[[1, 2, 3, 4]]);
    assert_eq!(
        classify_dns_response(&resp, TYPE_AAAA),
        DnsResponseClass::Empty
    );
}

#[test]
fn extract_ip_bytes_reads_a_and_aaaa_rdata() {
    let q = encode_dns_query("a.com", TYPE_A, 3);
    let resp = a_response(&q, &[[31, 13, 95, 169], [8, 8, 8, 8]]);
    assert_eq!(
        extract_answer_ip_bytes(&resp),
        vec![vec![31, 13, 95, 169], vec![8, 8, 8, 8]]
    );
    // RCODE!=0 → 不抽（不给 decoy 判定喂错误来源）。
    assert!(extract_answer_ip_bytes(&build_servfail(&q)).is_empty());
}

#[test]
fn servfail_echoes_question_and_sets_rcode2() {
    let q = encode_dns_query("node.example.com", TYPE_A, 0xabcd);
    let sf = build_servfail(&q);
    assert_eq!(u16_at(&sf, 0), Some(0xabcd), "id 回声");
    assert_eq!(u16_at(&sf, 2).unwrap() & 0x000f, RCODE_SERVFAIL);
    assert_eq!(u16_at(&sf, 2).unwrap() & 0x8000, 0x8000, "QR=1");
    assert_eq!(u16_at(&sf, 4), Some(1), "QDCOUNT=1");
    assert_eq!(u16_at(&sf, 6), Some(0), "ANCOUNT=0");
    assert_eq!(sf.len(), q.len(), "截到 question 末（本样本 query 无 OPT）");
}

#[test]
fn servfail_on_malformed_query_never_panics() {
    for len in 0..12usize {
        let sf = build_servfail(&vec![0xffu8; len]);
        assert!(sf.len() >= 12, "至少补足 header");
        assert_eq!(u16_at(&sf, 4), Some(0), "畸形 → QDCOUNT=0");
    }
}

#[test]
fn set_message_id_replaces_first_two_bytes_only() {
    let q = encode_dns_query("a.com", TYPE_A, 1);
    let resp = a_response(&q, &[[1, 1, 1, 1]]);
    let out = set_dns_message_id(&resp, 0x9999);
    assert_eq!(u16_at(&out, 0), Some(0x9999));
    assert_eq!(&out[2..], &resp[2..], "仅前两字节变");
}

#[test]
fn answer_response_uses_compression_pointer() {
    let q = encode_dns_query("a.com", TYPE_A, 5);
    let resp = a_response(&q, &[[9, 9, 9, 9]]);
    assert_eq!(u16_at(&resp, 6), Some(1), "ANCOUNT=1");
    assert_eq!(
        &resp[q.len()..q.len() + 2],
        &[0xc0, 0x0c],
        "name = 指针 0xC00C"
    );
    assert_eq!(classify_dns_response(&resp, TYPE_A), DnsResponseClass::Hit);
}

#[test]
fn skip_name_rejects_unterminated_name_and_never_follows_pointers() {
    // 无 root 标签、长度字节把 off 推出界的畸形名 → **必须** None（不死循环、不 panic）。
    // 旧断言 `is_none() || unwrap() <= len+2` 是恒真式（任何 Some(≤10) 都能过），锁不住任何东西。
    assert_eq!(skip_name(&[1u8; 8], 0), None, "无 root 终止 → None");
    assert_eq!(
        skip_name(&[3u8, b'a', b'b'], 0),
        None,
        "标签长度越界 → None"
    );
    assert_eq!(skip_name(&[], 0), None, "空 buf → None");

    // 正常名：`3 a b c 0` → 名字后偏移 = 5。
    assert_eq!(skip_name(&[3, b'a', b'b', b'c', 0], 0), Some(5));
    // 根标签单字节名 → 1。
    assert_eq!(skip_name(&[0], 0), Some(1));

    // 【核心语义：压缩指针**不追随**】自指指针 0xC000（指向自己）→ 恒返回 off+2、绝不解引用。
    // 变异验证：把 `skip_name` 的 `return Some(off + 2)` 改成 `off = (指针目标) as usize; continue`
    // → 本断言立刻死循环/超时转红。
    assert_eq!(
        skip_name(&[0xC0, 0x00], 0),
        Some(2),
        "指针占 2 字节且不追随"
    );
    // 指针出现在标签之后：`1 a C0 00` → 2(标签) + 2(指针) = 4。
    assert_eq!(skip_name(&[1, b'a', 0xC0, 0x00], 0), Some(4));
    // 指针目标落在缓冲区外也不追随（不越界读、不 panic）。
    assert_eq!(skip_name(&[0xC0, 0xFF], 0), Some(2));
}

#[test]
fn servfail_qdcount_zero_when_question_truncated_after_qname() {
    // qname 完整（`01 61 00`）但 qtype/qclass 被截：12 + 3 + 2 = 17 字节。
    // 旧判据 `end >= 16` 会 clamp 到 17 → 误置 QDCOUNT=1，产出「声称有 question 但 question 残缺」
    // 的畸形 SERVFAIL（内核丢弃 → 退化为超时）。完整判据须看 qname 之后是否真有 4 字节。
    let mut truncated = vec![0u8; 12];
    put_u16(&mut truncated, 4, 1); // 原 query 的 QDCOUNT=1
    truncated.extend_from_slice(&[0x01, b'a', 0x00]); // qname "a."
    truncated.extend_from_slice(&[0x00, 0x01]); // qtype=A，但 qclass 整个缺失
    assert_eq!(truncated.len(), 17, "完整 question 需 19 字节（12+3+2+2）");

    let sf = build_servfail(&truncated);
    assert_eq!(
        u16_at(&sf, 4),
        Some(0),
        "question 不完整 → QDCOUNT 必须为 0，不得产出残缺 question"
    );
    assert_eq!(u16_at(&sf, 2).unwrap() & 0x000f, RCODE_SERVFAIL);

    // 边界另一侧：question 恰好完整（补满 qclass 的 2 字节）→ QDCOUNT=1。
    let mut complete = truncated.clone();
    complete.extend_from_slice(&[0x00, 0x01]);
    assert_eq!(complete.len(), 19);
    assert_eq!(
        u16_at(&build_servfail(&complete), 4),
        Some(1),
        "question 完整 → QDCOUNT=1"
    );
}

#[test]
fn answer_response_resets_qdcount_to_one() {
    // QDCOUNT>1 的 query：build_answer_response 只回声**首个** question，故计数必须重置为 1，
    // 否则响应声称 2 个 question 却只带 1 个 → 畸形。
    let mut q = encode_dns_query("a.com", TYPE_A, 11);
    put_u16(&mut q, 4, 2); // 伪造 QDCOUNT=2
    let resp = a_response(&q, &[[5, 5, 5, 5]]);
    assert_eq!(u16_at(&resp, 4), Some(1), "QDCOUNT 必须重置为 1");
    assert_eq!(u16_at(&resp, 6), Some(1), "ANCOUNT=1");
    // 重置后整包自洽 → 仍可被自己的分类器判 HIT（QDCOUNT=2 时 skip_name 会多跳一个 question 而错位）。
    assert_eq!(classify_dns_response(&resp, TYPE_A), DnsResponseClass::Hit);
}
