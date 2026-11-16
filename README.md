# nts — Rust 实现的 NTS（Network Time Security，RFC 8915）

一个完整的 NTS 客户端/服务端实现，覆盖 **NTS-KE（TLS 1.3 上的密钥建立）** 与
**NTS 保护的 NTPv4（AEAD 认证报文）** 两个阶段，已与公开实现 **chrony 4.9**
在回环环境双向互通，并通过 RFC 5297 / GnuTLS 官方密码学向量校验。

## 支持的 AEAD 算法

| 算法 | NTS id | 密钥长度 | nonce | 说明 |
|---|---|---|---|---|
| `AEAD_AES_128_GCM` | 16 | 16 B | 12 B | ring 提供，RFC 5116 |
| `AEAD_AES_SIV_CMAC_256` | 15 | 32 B（AES-128-SIV，K1‖K2） | 可变（NTS 用 16 B） | 手写 S2V/CMAC/CTR，RFC 5297 |

两者都是 RFC 8915 的强制/推荐算法。SIV 实现以 AES-128-SIV 实例化，与
chrony/GnuTLS 对 id 15 的处理一致（`GNUTLS_CIPHER_AES_128_SIV`）。

## 架构

```
src/
  constants.rs     NTS-KE 记录号、AEAD id、EF 类型、exporter label 等线协议常量
  aead.rs          AES-128-GCM 与 AES-128-SIV（含 RFC5297 S2V/dbl/CTR、常量时间校验）
  keyderive.rs     RFC8915 §5.1 两次 TLS-Exporter 直接派生 C2S/S2C 工作密钥
  cert.rs          rcgen 自签证书、rustls TLS1.3-only + ALPN ntske/1、信任配置
  ke.rs            NTS-KE 记录帧（critical 位、EOM、自定界读写）
  ke_client.rs     NTS-KE 客户端：TLS 握手 → 协商 → exporter → cookie
  ke_server.rs     NTS-KE 服务端：校验请求 → 铸 cookie → 回协商结果
  ntp.rs           NTPv4 头与扩展字段（UID/Cookie/Placeholder/认证器）编解码
  ntp_client.rs    NTS NTP 客户端：组包、AEAD 密封、超时重试、偏移/RTT 计算
  ntp_server.rs    NTS NTP 服务端：cookie 验真、C2S 解封、S2C 密封响应
  cookie.rs        cookie 信封（AES-256-SIV 主密钥）、主密钥库、轮转与文件持久化
  time_util.rs     NTP 64 位时间戳、2036 纪元处理、on-wire 偏移/RTT、时钟抽象
  stats.rs         均值/标准差/百分位/RFC5905 抖动
tests/
  end_to_end.rs            回环 KE+NTP 端到端、SIV 协商、轮转过渡、篡改拒绝
  gnutls_siv_vectors.rs    与 GnuTLS AES-128-SIV 输出逐字节比对
```

### 关键设计点

- **工作密钥**：直接来自两次 TLS-Exporter（context 末字节 `0x00`/`0x01`），
  不在 exporter 外再套 HKDF（这是与 chrony 互通的关键，RFC 8915 §5.1）。
- **Cookie 是可复用不透明令牌**：内嵌独立的 32 字节 SIV nonce，与每次 NTP
  请求随机变化的 Unique Identifier 解耦；整体 4 字节对齐（chrony 强制）。
- **主密钥共享**：KE 与 NTP 进程通过同一个原子写入的密钥文件
  （`NTSK` 格式）共享主密钥；NTP 侧周期 `reload` 拾取轮转。
- **轮转过渡**：新密钥铸造新 cookie，旧密钥在 overlap 窗口内保留，
  旧 cookie 持续可验，到期后 `prune_expired` 清除。
- **AAD 范围**：AEAD 关联数据是认证器之前的整个包前缀（48B 头 + 明文 EF），
  与 chrony `assoc_length = info->length` 一致。
- **EF 不设 last-field 标记**：NTS 扩展字段纯靠长度界定，type 高位恒清零。

## 构建与测试

```bash
cargo build --release
cargo test                 # 35 个单元/集成/向量测试
```

## 命令行用法

```bash
# 1) 生成自签证书（含 serverAuth EKU、IP/DNS SAN）
./target/release/nts gen-cert --common-name 127.0.0.1 \
    --cert-out ke-cert.pem --key-out ke-key.pem

# 2) 启动 NTS-KE 服务（TLS 14460），与 NTP 服务共享主密钥文件
./target/release/nts ke-server \
    --listen 127.0.0.1:14460 \
    --cert ke-cert.pem --key ke-key.pem \
    --ntp-port-hint 14123 \
    --key-store nts-keys.bin

# 3) 启动 NTS NTP 服务（UDP），周期 reload 轮转密钥
./target/release/nts ntp-server \
    --listen 127.0.0.1:14123 \
    --key-store nts-keys.bin --reload-ms 1000

# 4) 客户端：KE 取 cookie，然后做 N 次认证 NTP 查询
./target/release/nts client \
    --ke-host 127.0.0.1 --ke-port 14460 \
    --ntp-addr 127.0.0.1:14123 \
    --pin-cert ke-cert.pem \
    --count 40 --interval-ms 100 --json-out samples.json

# 5) 轮转主密钥（旧 cookie 在 overlap 期仍有效）
./target/release/nts rotate-keys --key-store nts-keys.bin

# 6) 单进程端到端演示（含中途轮转）
./target/release/nts demo --count 20 --rotate-midway
```

## 与 chrony 4.9 互通测试

chrony 作为 NTS 客户端、本实现作为服务端（非特权、回环、不控制系统时钟）：

```bash
# chrony.conf（关键行）
ntstrustedcerts 1 /path/ke-cert.pem
server 127.0.0.1 nts certset 1 ntsport 14460 port 14123 minpoll 0 maxpoll 2
cmdport 1323
bindcmdaddress 127.0.0.1

chronyd -U -x -f chrony.conf -n          # -U 跳过 root 检查，-x 不改系统时钟
chronyc -h 127.0.0.1 -p 1323 sources     # 出现 ^* 即同步成功
```

实测 chrony 收敛到 `^*`、Reach 377、Stratum 4、Leap Normal，NTP 服务端零
认证错误。详细时间质量数据见 [REPORT.md](REPORT.md)。

## 安全说明

- 私钥/主密钥内存用 `zeroize` 在 `Drop` 时清零。
- SIV 标签比较用 `subtle::ConstantTimeEq` 常量时间比较。
- 认证失败的 UDP 报文被静默丢弃（NTS 无带外错误通道），不回污染响应。
- 自签证书仅用于实验；生产应使用受信 CA 签发、带有效 SAN 的证书，
  客户端用 WebPKI 信任（`client_config_webpki`）。
