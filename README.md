# secret-vault: 敏感数据容器与内存残留验证

针对"内存转储里翻出数据库口令、会话密钥"这一真实问题的完整 Rust 方案。
包含三部分:

| 组件 | 作用 |
|---|---|
| [`secret-vault/`](secret-vault/) | 敏感数据容器库: 口令/密钥放进去后, 在复制、扩容、错误返回、异常退出各路径都不留明文副本, 且不被换出到磁盘 |
| [`memscan/`](memscan/) | 内存残留扫描库 + CLI: 遍历进程可读内存区域搜索哨兵值, 用于证明 "清干净了" |
| [`demo-service/`](demo-service/) | 同一认证服务的 naive / hardened 两套实现, 分阶段抓内存做前后对比 |
| [`tools/`](tools/) | lldb 外部取证脚本: 攻击者/取证人员视角, 不依赖目标进程配合 |

---

## 1. 威胁模型与对应措施

| 威胁 | 机制 | 代码位置 |
|---|---|---|
| 内存转储 (`gcore`/lldb/崩溃 core) 出现明文 | 数据页 `mlock`; Linux `MADV_DONTDUMP`; 进程 `RLIMIT_CORE=0` | `secret-vault/src/alloc.rs`, `harden.rs` |
| swap 换出到磁盘 | 每次分配对数据页 `mlock` (非 `mlockall`, 不影响无关内存) | `alloc.rs` |
| 扩容后旧缓冲区残留 | 只走 mmap; 扩容 = 新映射 + 迁移 + 旧区易失写清零 + munmap | `buf.rs::reserve` |
| 编译器把清零优化掉 | `write_volatile` + `compiler_fence`, 语义上禁止死存储消除 | `alloc.rs::explicit_zero` |
| 自由链表/分配器复用泄漏 | 不经过 malloc, 区域生命周期完全自控 | `alloc.rs` |
| `Debug`/日志意外打印 | 所有容器 `Debug`/`Display` 固定输出 `REDACTED` | `buf.rs`, `string.rs`, `secret_box.rs` |
| panic unwind 跳过析构 | workspace 配置 `panic = "abort"`, 进程即死, 匿名页随进程回收 | `Cargo.toml` |
| 口令比较计时侧信道 | `SecretBuf::ct_eq` 常量时间比较 | `buf.rs` |
| 越界读写波及相邻数据 | 可选 guard page (`PROT_NONE`), 越界即 SIGBUS/SIGSEGV | `alloc.rs` |

### 用到的系统能力 (按平台)

| 能力 | Linux | macOS |
|---|---|---|
| 匿名私有映射 | `mmap(MAP_ANON\|MAP_PRIVATE)` | 同左 |
| 锁页防换出 | `mlock` / `munlock` | 同左 |
| 从 core dump 排除 | `madvise(MADV_DONTDUMP)` + `RLIMIT_CORE=0` | 仅 `RLIMIT_CORE=0` (无 per-region 接口) |
| 禁核心转储 | `setrlimit(RLIMIT_CORE,0)`, 可选 `prctl(PR_SET_DUMPABLE,0)` | `setrlimit(RLIMIT_CORE,0)` |
| 内存区域枚举 | 解析 `/proc/self/maps` | Mach `mach_vm_region` + `proc_regionfilename` |
| 按地址读内存 | `pread(/proc/self/mem)` | `mach_vm_read_overwrite` |
| 外部取证 | gcore / lldb | lldb / vmmap |

> macOS 的 swap 本身是加密的 (`sysctl vm.swapusage` 显示 encrypted),
> `mlock` 在此基础上进一步保证敏感页根本不进 swap。

---

## 2. 容器类型

```rust
SecretBuf       // 任意长度敏感字节, 支持 reserve/push/truncate, 扩容即清零旧区
SecretString    // UTF-8 文本秘密 (口令、API key), reveal() 是审计锚点
SecretBox<T>    // 定长 Copy 类型 (如 [u8; 32] 密钥), 单页分配
SecretKey<N>    // SecretBox<[u8; N]> 的类型别名
```

核心不变量: 有效字节永远只位于某个 `mmap + mlock` 的受保护页;
任何存储变动 (clone/扩容/truncate/drop) 都对旧内容做不可优化的清零后再 munmap。

---

## 3. 验证方法论 (关键)

内存扫描有个固有矛盾: **扫描器必须先把字节读进自己的缓冲才能搜索**,
于是扫描期间该缓冲会回显被测内容。本项目用三条独立证据链解决:

1. **受保护暂存页**: 扫描器的读缓冲也走 `secret-vault` 的 mmap+mlock 页
   (`memscan/src/scratch.rs`), 回显不落 malloc 堆, 扫描结束整页清零。
2. **活容器判据** (`ScanReport::live_container_hits`): 真正的容器是独立
   页级 mmap (区域 ≤64KB 且命中地址页对齐); 扫描器/堆的瞬态缓冲在 MB 级
   malloc arena, 据此精确区分 "活容器持有的明文" 与 "瞬态回声"。
3. **外部独立取证** (`tools/lldb_dump.sh`): 用 lldb 从进程外部抓全部可写
   内存, 离线搜索, 完全不依赖目标进程自报。

哨兵值全部**运行时生成** (高熵可打印 ASCII, `demo-service/src/sentinel.rs`),
避免字符串字面量被编进二进制 `__TEXT` 段——那种残留任何容器都管不到,
本身也是一条要演示的教训。

---

## 4. 快速上手

```bash
# 全量构建 + 测试 (19 个测试: 单元/搜索器/端到端清零)
cargo test

# 系统能力自检: core 限制、mlock、容器清零
cargo run -p demo-service -- doctor

# 改造前后分阶段内存残留对比
cargo run -p demo-service -- compare

# 单模式详细报告
cargo run -p demo-service -- run naive
cargo run -p demo-service -- run hardened

# 扫描器 CLI (hex 模式, 避免秘密出现在 argv)
cargo run -p memscan -- regions
cargo run -p memscan -- lock-info
cargo run -p memscan -- self --hex <HEX...>

# 外部 lldb 取证 (持有期 + 关闭后两次抓取)
./tools/external_verify.sh hardened
./tools/external_verify.sh naive
```

### 实测对比 (Apple Silicon, macOS)

```
stage       |  naive (pwd/key/token) | hardened (pwd/key/token) | 残留削减
bootstrap   |         3 / 3 / 3      |        2 / 2 / 2         | 33%
replicate   |         4 / 3 / 3      |        2 / 2 / 2         | 40%
after-drop  |         3 / 2 / 2      |        1 / 1 / 1         | 57%
```

- naive 命中全部落在 4MB 级普通堆匿名区, drop 后字节仍在;
- hardened 的每处明文都在独立 16KB 受保护小页, **服务关闭后业务残留 = 0**
  (剩余的 1 处是扫描模式自身的容器, 非业务数据)。

外部 lldb 取证结果:

```
hardened 持有期: 3 处命中, 全部在 受保护小页(mlock), 0 处在普通堆
hardened 关闭后: 0 处命中
naive    持有期: 7 处命中, 全部在 普通堆/大匿名区
```

异常退出: `abort-hardened` 在持有秘密时 panic, 进程以 134 (SIGABRT) 退出,
`/cores` 无文件产生 (`RLIMIT_CORE=0` 生效)。

---

## 5. 库管不到的边界 (调用方责任)

1. **进入容器之前的明文**: argv、环境变量、普通 `String` 配置解析都会留痕。
   应改用 `from_reader*` / `from_hex` 从源头直接落地, 入容器后立即清零源。
2. **`reveal()`/`expose()`/`as_bytes()` 借出期间**: 调用方若把内容拷进普通
   内存, 那份副本不受保护。demo 的 HMAC 签名演示了正确做法: 借出到栈数组,
   用完立刻 `zeroize`。
3. **内核态缓冲**: socket 接收缓冲、终端行规程不在本库控制范围。
4. **硬编码在二进制里的秘密**: 在 `__TEXT` 段, 任何运行时容器都无法清除。

---

## 6. 目录结构

```
secret-vault/
  src/alloc.rs        页面级分配器 (mmap/mlock/guard/清零)
  src/buf.rs          SecretBuf
  src/string.rs       SecretString
  src/secret_box.rs   SecretBox<T> / SecretKey<N>
  src/harden.rs       RLIMIT_CORE、mlock 统计、(Linux) PR_SET_DUMPABLE
  src/error.rs        错误类型 (带 errno)
  tests/zeroization.rs  端到端清零集成测试
memscan/
  src/backend_macos.rs  Mach VM 枚举+读取
  src/backend_linux.rs  /proc/maps + /proc/mem
  src/scratch.rs        受保护扫描暂存页
  src/search.rs         aho-corasick 多模式流式搜索 (零整块拷贝)
  src/lib.rs            ScanReport / live_container_hits
demo-service/
  src/naive.rs        改造前: 典型泄漏模式 (clone/format/扩容/错误路径)
  src/hardened.rs     改造后: 全程受保护容器
  src/sentinel.rs     运行时高熵哨兵
  src/main.rs         run/compare/doctor/hold/abort-hardened 子命令
tools/
  lldb_dump.sh / lldb_dump.py  外部内存抓取 + 离线搜索
  external_verify.sh           两阶段外部取证编排
```
