# NTS 实现互通与时间质量对比报告

测试日期：2026-11-16
被测实现：本仓库 Rust NTS（RFC 8915）客户端 + 服务端
公开实现对照：**chrony 4.9**（Homebrew 构建，含 `+NTS`，GnuTLS 后端）
网络环境：macOS arm64，全部回环地址 `127.0.0.1`，KE 端口 14460 / NTP 高位 UDP 端口 14123
（沙箱封禁出站 UDP/123，因此互通在本地回环完成；chrony 以非特权方式 `-U -x` 运行，不控制系统时钟）

## 1. 协议符合性验证

| 检查项 | RFC 8915 要求 | 本实现 | 结果 |
|---|---|---|---|
| 传输层 | TLS 1.3，ALPN `ntske/1` | rustls 强制 TLS1.3-only + ALPN | ✅ TLS1.2 被 alert 70 拒绝 |
| KE 记录编号 | EOM=0, NextProto=1, Error=2, Warning=3, AEAD=4, Cookie=5, Server=6, Port=7 | 常量与 §4.1 完全对齐 | ✅ |
| Next Protocol | 请求/响应各含一条 NTPv4(id 0) | 已实现并校验 | ✅ |
| 密钥提取 | 两次 TLS-Exporter，context 5 字节，末字节 0x00/0x01 | 直接 exporter，无额外 HKDF | ✅ 与 chrony 互通 |
| AEAD id 15 | AES-SIV-CMAC（chrony 映射 AES-128-SIV，32B 密钥） | AES-128-SIV，S2V/CMAC/CTR 手写 | ✅ 与 GnuTLS 逐字节一致 |
| AEAD id 16 | AES-128-GCM，16B 密钥，12B nonce | ring 实现 | ✅ |
| SIV 参考向量 | RFC 5297 附录 A.1/A.2 | 测试全部通过 | ✅ |
| GnuTLS 交叉向量 | AES-128-SIV 空/非空明文 | `tests/gnutls_siv_vectors.rs` 逐字节匹配 | ✅ |
| Cookie | 可复用不透明令牌、4 字节对齐 | 内嵌独立 SIV nonce，尾部 4 对齐填充 | ✅ chrony 接受 |
| 主密钥轮转 | 旧 cookie 在过渡期仍有效 | 文件共享库 + overlap，NTP 侧周期 reload | ✅ 见 §3 |
| NTP 认证器 | AAD = 认证器前整包前缀 | 按 chrony `assoc_length=info->length` 实现 | ✅ |
| EF 帧 | 长度界定，不设 RFC7822 last-bit | type 高位始终清零 | ✅ 与 chrony 抓包一致 |

## 2. 时间质量：两个客户端对照同一台 Rust NTS 服务器

### 2.1 本仓库 Rust 客户端（60 次采样，约 80ms 间隔）

| 指标 | 数值 |
|---|---|
| 样本数 | 60（全部认证通过，无失败重试耗尽） |
| 偏移均值 (mean offset) | **+14.158 µs** |
| 偏移范围 | −1.113 ms … +147.000 µs |
| 偏移标准差 (stddev) | 152.861 µs |
| RFC5905 抖动 (jitter) | 54.666 µs |
| RTT 均值 | 445.950 µs |
| RTT 最小 / 中位 / P95 / 最大 | 146 µs / 372 µs / 795 µs / 2.563 ms |
| Cookie 罐 | 全程稳定 8 个（placeholder 轮换生效） |

### 2.2 chrony 客户端（同一服务器，长时间收敛后）

| 指标 | 数值 |
|---|---|
| 源选择状态 | `^*`（已选中并同步），Reach 377/360（全可达） |
| Stratum | 4（服务器 stratum 3 + 1） |
| Leap | Normal |
| 单次偏移 (Last offset) | −1.649 µs |
| RMS 偏移 | 34.528 µs |
| 源偏移 (sourcestats Offset) | −165 ns |
| 源标准差 (Std Dev) | 19 µs |
| Root delay / dispersion | 264 µs / 68.4 µs |

### 2.3 对比解读

- **正确性一致**：两个客户端对同一台服务器测得的偏移都落在亚毫秒级、中心值在 ±几十 µs 内，方向与量级吻合，证明 on-wire 时间戳计算（标准四时间戳 offset/RTT 公式）正确。
- **离散度差异来自滤波，而非协议**：Rust 客户端输出的是**原始逐样本**统计（含调度抖动造成的 −1.1 ms 离群点），stddev 因此偏大；chrony 展示的是经过多源回归、离群剔除和指数平滑后的**收敛估计**，所以 Std Dev 仅 19 µs、偏移收敛到纳秒级。这是客户端时间同步算法层的差别，不是 NTS 认证或 NTP 报文的差别。
- **RTT**：回环下中位 RTT 仅 372 µs，P95 < 0.8 ms，链路本身极快；个别毫秒级峰值来自本机进程调度。
- 若让 Rust 客户端也做 chrony 同等的滤波（中值/截尾均值 + 指数平滑），其稳态精度可达到同一量级；本报告如实区分“原始测量”与“滤波估计”。

## 3. 主密钥轮转与 cookie 过渡期

1. 初始共享密钥库仅含 key id 1，KE 用它铸造 cookie。
2. 执行 `nts rotate-keys`：库变为 `[1, 2]`，新 cookie 用 id 2 铸造，id 1 在 overlap 窗口内保留。
3. NTP 服务端在 300ms 内 `reload` 共享文件，识别新密钥。
4. 轮转后：
   - Rust 客户端重新 KE 取得新 cookie，4/4 查询全部成功；
   - chrony 持续保持 `^*` 选中态、Reach 360，无同步中断；
   - 干净观测窗口内 NTP 服务端**零认证错误**。
5. 单元测试 `persisted_store_is_shared_and_rotation_is_reloaded` 与
   `cookies_minted_before_rotation_remain_valid_afterward` 自动覆盖“旧 cookie
   在过渡期仍可验证、新 cookie 走新密钥”的语义。

## 4. 测试资产

- 库内单元/集成测试 35 个，含 RFC 5297 官方向量、GnuTLS AES-128-SIV 交叉向量、
  端到端 KE+NTP、轮转过渡期、篡改拒绝。
- 复现命令见 `README.md` 的“互通测试”章节。
