//! X25519（Curve25519 ECDH，RFC 7748）—— WARP 设备密钥对生成用。
//!
//! # 为什么自带实现而非 ring
//!
//! WARP 即 WireGuard：注册一台匿名设备要产出一份 **可持久化的 WG 私钥**（随节点落
//! `wireguardSettings.privateKey`，base64 的 32 字节裸标量）。上游 用 node
//! `crypto.generateKeyPairSync('x25519')` 取 PKCS8/SPKI DER 末 32 字节裸 key
//! （见 `WarpService.generateKeyPair`）。
//!
//! 本仓唯一的密码学栈是 `ring`（随 rustls 入图）。但 ring 的 `agreement::EphemeralPrivateKey`
//! **刻意不暴露私钥字节**（`bytes()` 是 `#[cfg(test)] + #[deprecated]`，生产构建取不到），
//! 也没有从裸标量导入的静态 X25519 密钥类型 —— 它的 API 契约就是「私钥只用于一次 agree、永不导出」。
//! 而 WG 恰恰要导出并持久化私钥。故 ring 的 agreement 无法满足 [`crate::runtime::mesh::SeededWarpKeypair`]
//! 的契约（返回 `(private_b64, public_b64)`）。
//!
//! 因此这里放一份 **RFC 7748 X25519 标量乘**：`ring` 只用来出 32 字节随机源（CSPRNG），
//! 公钥由本函数从随机标量算出。**不引入新依赖**（TweetNaCl `crypto_scalarmult` 直译，纯 std）。
//! 由 RFC 7748 §5.2 / §6.1 官方测试向量钉死（打断阶梯任一步即转红）。
//!
//! # 私钥不裁剪、公钥裁剪
//!
//! 与 node 一致：**存储的私钥是未裁剪的 32 随机字节**（node PKCS8 末 32 字节即裸种子），
//! 公钥 = X25519(种子, 基点 9)，标量乘内部按 RFC 7748 裁剪种子。sing-box/wireguard-go
//! 用私钥时也会裁剪 → 存裁剪与否不影响互通（公钥与行为一致）。

// TweetNaCl `crypto_scalarmult` 的忠实移植：索引式 limb 运算 + 单字母 gf 变量是参考实现的
// 内在形态（RFC 7748 附录同款），迭代器化/改名只会降低与权威实现的可对照性、增加移植错位风险。
#![allow(clippy::needless_range_loop)]
#![allow(clippy::many_single_char_names)]
#![forbid(unsafe_code)]

/// 域元素：radix-2^16 的 16 个 i64 limb（TweetNaCl `gf`）。
type Gf = [i64; 16];

/// 常量 a24 = 121665 = 0x1DB41 = limb0 0xDB41 + limb1 1。
const A24: Gf = [0xDB41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

/// X25519 基点 u=9（小端 32 字节）。
const BASE_POINT: [u8; 32] = [
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// 进位归约（TweetNaCl `car25519`，含负数偏置技巧：先 +2^16 再减回）。
fn car25519(o: &mut Gf) {
    for i in 0..16 {
        o[i] += 1 << 16;
        let c = o[i] >> 16;
        // i<15 → 进位入 o[i+1]；i==15 → 环回 o[0] 并乘 37（2^256 ≡ 38，此处 37=38-1 配偏置）。
        let idx = (i + 1) * usize::from(i < 15);
        o[idx] += c - 1 + 37 * (c - 1) * i64::from(i == 15);
        o[i] -= c << 16;
    }
}

/// 常量时间条件交换（b∈{0,1}；b=1 交换 p/q）。TweetNaCl `sel25519`。
fn sel25519(p: &mut Gf, q: &mut Gf, b: i64) {
    let c = !(b - 1); // b=1 → -1（全 1，交换）；b=0 → 0（不动）
    for i in 0..16 {
        let t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

/// 小端 32 字节 → gf（清高位，u 坐标 mask 到 255 bit）。TweetNaCl `unpack25519`。
fn unpack25519(n: &[u8; 32]) -> Gf {
    let mut o: Gf = [0; 16];
    for i in 0..16 {
        o[i] = i64::from(n[2 * i]) + (i64::from(n[2 * i + 1]) << 8);
    }
    o[15] &= 0x7fff;
    o
}

/// gf → 小端 32 字节（含最终 mod p 归约的两轮条件减 p）。TweetNaCl `pack25519`。
fn pack25519(n: &Gf) -> [u8; 32] {
    let mut t: Gf = *n;
    car25519(&mut t);
    car25519(&mut t);
    car25519(&mut t);
    for _ in 0..2 {
        let mut m: Gf = [0; 16];
        m[0] = t[0] - 0xffed;
        for i in 1..15 {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        let b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        sel25519(&mut t, &mut m, 1 - b);
    }
    let mut o = [0u8; 32];
    for i in 0..16 {
        o[2 * i] = (t[i] & 0xff) as u8;
        o[2 * i + 1] = (t[i] >> 8) as u8;
    }
    o
}

fn add(a: &Gf, b: &Gf) -> Gf {
    let mut o: Gf = [0; 16];
    for i in 0..16 {
        o[i] = a[i] + b[i];
    }
    o
}

fn sub(a: &Gf, b: &Gf) -> Gf {
    let mut o: Gf = [0; 16];
    for i in 0..16 {
        o[i] = a[i] - b[i];
    }
    o
}

/// gf 乘（学生乘 + 折叠 2^256≡38 + 两轮进位）。TweetNaCl `M`。
fn mul(a: &Gf, b: &Gf) -> Gf {
    let mut t = [0i64; 31];
    for i in 0..16 {
        for j in 0..16 {
            t[i + j] += a[i] * b[j];
        }
    }
    for i in 0..15 {
        t[i] += 38 * t[i + 16];
    }
    let mut o: Gf = [0; 16];
    o.copy_from_slice(&t[..16]);
    car25519(&mut o);
    car25519(&mut o);
    o
}

fn sqr(a: &Gf) -> Gf {
    mul(a, a)
}

/// 模逆（费马小定理 x^(p-2)，固定 254 次平方 + 选择性乘）。TweetNaCl `inv25519`。
fn inv25519(i: &Gf) -> Gf {
    let mut c: Gf = *i;
    for a in (0..=253).rev() {
        c = sqr(&c);
        if a != 2 && a != 4 {
            c = mul(&c, i);
        }
    }
    c
}

/// X25519 标量乘：`scalar`（内部按 RFC 7748 裁剪）× `point`（u 坐标）。TweetNaCl `crypto_scalarmult`。
fn crypto_scalarmult(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    // RFC 7748 decodeScalar25519：clamp（低 3 bit 清 0、bit254 置 1、bit255 清 0）。
    let mut z = *scalar;
    z[0] &= 248;
    z[31] = (z[31] & 127) | 64;

    let xp = unpack25519(point);
    let mut a: Gf = [0; 16];
    let mut b: Gf = xp;
    let mut c: Gf = [0; 16];
    let mut d: Gf = [0; 16];
    a[0] = 1;
    d[0] = 1;

    // 蒙哥马利阶梯（bit 254..0）。
    for i in (0..=254).rev() {
        let r = ((z[i >> 3] >> (i & 7)) & 1) as i64;
        sel25519(&mut a, &mut b, r);
        sel25519(&mut c, &mut d, r);
        let mut e = add(&a, &c);
        a = sub(&a, &c);
        c = add(&b, &d);
        b = sub(&b, &d);
        d = sqr(&e);
        let f = sqr(&a);
        a = mul(&c, &a);
        c = mul(&b, &e);
        e = add(&a, &c);
        a = sub(&a, &c);
        b = sqr(&a);
        c = sub(&d, &f);
        a = mul(&c, &A24);
        a = add(&a, &d);
        c = mul(&c, &a);
        a = mul(&d, &f);
        d = mul(&b, &xp);
        b = sqr(&e);
        sel25519(&mut a, &mut b, r);
        sel25519(&mut c, &mut d, r);
    }

    // x2 * (z2^(p-2))。
    let cinv = inv25519(&c);
    let res = mul(&a, &cinv);
    pack25519(&res)
}

/// X25519 标量乘（RFC 7748）：`scalar` × `point`。`scalar` 内部裁剪。
#[cfg(test)]
#[must_use]
pub fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    crypto_scalarmult(scalar, point)
}

/// 由私钥标量算 X25519 公钥（× 基点 9）。WG keygen 用。
#[must_use]
pub fn x25519_base(scalar: &[u8; 32]) -> [u8; 32] {
    crypto_scalarmult(scalar, &BASE_POINT)
}

#[cfg(test)]
mod tests;
