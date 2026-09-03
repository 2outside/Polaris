use super::*;

/// 十六进制字符串 → 32 字节（测试向量用）。
fn hex32(s: &str) -> [u8; 32] {
    let bytes = s.as_bytes();
    assert_eq!(bytes.len(), 64, "需 64 hex 字符");
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = (bytes[2 * i] as char).to_digit(16).unwrap() as u8;
        let lo = (bytes[2 * i + 1] as char).to_digit(16).unwrap() as u8;
        out[i] = (hi << 4) | lo;
    }
    out
}

#[test]
fn rfc7748_section5_2_vector1() {
    // RFC 7748 §5.2 首条测试向量：X25519(scalar, u) == 期望输出。
    // 打断阶梯任一步（car/mul/inv/ladder）→ 输出偏离 → 转红。
    let scalar = hex32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    let u = hex32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    let expected = hex32("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
    assert_eq!(x25519(&scalar, &u), expected);
}

#[test]
fn rfc7748_section5_2_vector2() {
    let scalar = hex32("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
    let u = hex32("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
    let expected = hex32("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
    assert_eq!(x25519(&scalar, &u), expected);
}

#[test]
fn rfc7748_section6_1_base_point_keygen() {
    // §6.1：由私钥算公钥（× 基点 9）。这是 WARP keygen 走的确切路径。
    // x25519_base(alice_priv) 必须 == alice_pub，否则 sing-box 拒非法 x25519 公钥。
    let alice_priv = hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let alice_pub = hex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    assert_eq!(x25519_base(&alice_priv), alice_pub);

    // Bob 同理（双方公钥导出都对，且下方 DH 一致）。
    let bob_priv = hex32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    let bob_pub = hex32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    assert_eq!(x25519_base(&bob_priv), bob_pub);

    // DH 一致性：X25519(a, B) == X25519(b, A) == shared。
    let shared = hex32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    assert_eq!(x25519(&alice_priv, &bob_pub), shared);
    assert_eq!(x25519(&bob_priv, &alice_pub), shared);
}

#[test]
fn clamping_makes_low_bits_irrelevant_for_public_key() {
    // 存储私钥不裁剪但标量乘内部裁剪：同一种子改低 3 bit / 高 bit 不影响公钥。
    let mut seed = [7u8; 32];
    let pk1 = x25519_base(&seed);
    seed[0] ^= 0b0000_0111; // 低 3 bit（被 &248 清）
    seed[31] ^= 0b1100_0000; // bit255/bit254（被 clamp 覆盖）
    let pk2 = x25519_base(&seed);
    assert_eq!(pk1, pk2, "clamp 覆盖的位不应改变公钥");
}
