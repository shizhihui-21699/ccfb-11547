//! # secret-vault
//!
//! 敏感数据容器库: 口令、会话密钥、API key 一类值放进来之后,
//! 在 **复制、扩容、错误返回、异常退出** 的每一条路径上都不会留下明文副本。
//!
//! ## 威胁模型与对应措施
//!
//! | 威胁 | 措施 |
//! |---|---|
//! | 内存转储 (`gcore`/lldb/崩溃 core) 里出现明文 | 数据页 `mlock`; Linux `MADV_DONTDUMP`; 进程 `RLIMIT_CORE=0` |
//! | swap 换出到磁盘 | 每次分配对数据页 `mlock` (不是 `mlockall`, 不影响无关内存) |
//! | 扩容后旧缓冲区残留 | 只走 mmap; 扩容 = 新映射 + 拷贝 + 旧区 `explicit_bzero` + munmap |
//! | 编译器把清零优化掉 | libc `explicit_bzero`, 语义上禁止死存储消除 |
//! | `Debug`/日志意外打印 | 所有容器的 `Debug`/`Display` 固定输出 `REDACTED` |
//! | 析构没跑 (panic unwind 跳过) | workspace 配置 `panic = "abort"`, 进程立刻终止, 匿名页随进程回收 |
//! | 自由链表/分配器复用泄漏 | 不经过 malloc, 区域生命周期完全自控 |
//! | 比较口令的计时侧信道 | [`SecretBuf::ct_eq`] 常量时间比较 |
//!
//! ## 快速上手
//!
//! ```no_run
//! use secret_vault::{harden_process, SecretString};
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     harden_process()?; // 服务启动先加固: 禁 core dump
//!
//!     // 直接从 stdin 读口令, 不经过普通 String
//!     let password = SecretString::from_reader_utf8(&mut std::io::stdin().lock())?;
//!     check_password(&password);
//!     // password 离开作用域: explicit_bzero + munlock + munmap
//!     Ok(())
//! }
//!
//! fn check_password(p: &SecretString) {
//!     let expected = SecretString::from_utf8("correct horse battery staple").unwrap();
//!     assert!(p.ct_eq(&expected));
//! }
//! ```
//!
//! ## 库本身管不到的边界 (需要调用方遵守)
//!
//! 1. 进入容器**之前**的明文。argv、环境变量、普通 `String` 配置解析都会留痕,
//!    应改用 `from_reader*` / `from_hex` 从源头直接落地。
//! 2. `reveal()`/`expose()`/`as_bytes()` 借出期间, 调用方若把内容拷进普通
//!    内存, 那份副本不受保护。
//! 3. 内核态的 socket 接收缓冲、终端行规程缓冲不在本库控制范围内。

#![deny(unsafe_op_in_unsafe_fn)]
#![allow(missing_docs)]

mod alloc;
mod buf;
mod error;
mod harden;
mod secret_box;
mod string;

pub use buf::SecretBuf;
pub use error::{ErrorKind, Result, SecretError};
pub use harden::{disable_core_dumps, harden_process, locked_bytes, HardeningReport};
pub use secret_box::{SecretBox, SecretKey};
pub use string::SecretString;

#[cfg(target_os = "linux")]
pub use harden::set_non_dumpable;
