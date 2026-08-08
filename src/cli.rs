//! 命令行接口定义。
//!
//! 同一个二进制有两种运行模式：
//! - 给出 `-c/--config` → 以服务端（keyben-server）运行；
//! - 给出子命令（init / secrets / run）→ 以客户端运行。

use clap::{ArgAction, Parser, Subcommand, ValueEnum, builder::BoolishValueParser};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "keyben",
    version,
    about = "端到端加密的环境变量管理工具（单二进制：客户端 + 服务端）",
    long_about = "keyben —— 端到端加密的环境变量管理工具。\n\n\
                  服务端模式：keyben -c /etc/keyben/config.toml\n\
                  客户端模式：keyben init | keyben secrets ... | keyben run ...\n\n\
                  加解密全部在客户端完成（ChaCha20-Poly1305），服务端只存 Base64 密文。",
    after_help = "示例:\n  \
        keyben -c config.toml\n  \
        keyben --server http://127.0.0.1:8000 init --projectName myapp\n  \
        keyben secrets set --projectName myapp --env dev --name DB_URL --value 'postgres://...'\n  \
        keyben secrets get --projectName myapp --env dev\n  \
        keyben run --projectName myapp --env prod -- ./server --port 8080"
)]
pub struct Cli {
    /// 服务端配置文件路径；给出此参数即以服务端模式运行
    #[arg(short = 'c', long = "config", value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// 服务端地址，例如 http://127.0.0.1:8000
    #[arg(long, global = true, env = "KEYBEN_SERVER", value_name = "URL")]
    pub server: Option<String>,

    /// HTTP API 鉴权 Token
    #[arg(
        long,
        global = true,
        env = "KEYBEN_TOKEN",
        value_name = "TOKEN",
        hide_env_values = true
    )]
    pub token: Option<String>,

    /// 加解密密码；未提供时交互式隐藏输入
    #[arg(
        long,
        global = true,
        env = "KEYBEN_PASSWORD",
        value_name = "PASSWORD",
        hide_env_values = true
    )]
    pub password: Option<String>,

    /// 跳过 TLS 证书校验（仅用于自签证书的内网环境）
    #[arg(
        long,
        global = true,
        env = "KEYBEN_INSECURE",
        num_args = 0..=1,
        default_value = "false",
        default_missing_value = "true",
        value_parser = BoolishValueParser::new(),
        action = ArgAction::Set,
    )]
    pub insecure: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// 在服务端创建一个项目
    Init {
        /// 项目名
        #[arg(long = "projectName", value_name = "NAME")]
        project_name: String,
    },

    /// 管理项目的环境变量
    Secrets {
        #[command(subcommand)]
        action: SecretsCommand,
    },

    /// 注入解密后的环境变量并拉起子进程
    Run {
        /// 项目名
        #[arg(long = "projectName", value_name = "NAME")]
        project_name: String,

        /// 环境
        #[arg(long, value_enum)]
        env: Env,

        /// `--` 之后的程序及其参数
        #[arg(
            last = true,
            required = true,
            allow_hyphen_values = true,
            value_name = "COMMAND"
        )]
        argv: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum SecretsCommand {
    /// 加密并写入一个环境变量
    Set {
        /// 项目名
        #[arg(long = "projectName", value_name = "NAME")]
        project_name: String,

        /// 环境
        #[arg(long, value_enum)]
        env: Env,

        /// 变量名
        #[arg(long, value_name = "KEY")]
        name: String,

        /// 变量明文值
        #[arg(long, value_name = "VALUE")]
        value: String,
    },

    /// 读取并解密环境变量；不给 --name 则打印该环境下的全部变量
    Get {
        /// 项目名
        #[arg(long = "projectName", value_name = "NAME")]
        project_name: String,

        /// 环境
        #[arg(long, value_enum)]
        env: Env,

        /// 变量名；省略则以 KEY=VALUE 逐行打印全部变量
        #[arg(long, value_name = "KEY")]
        name: Option<String>,
    },

    /// 删除一个环境变量
    Delete {
        /// 项目名
        #[arg(long = "projectName", value_name = "NAME")]
        project_name: String,

        /// 环境
        #[arg(long, value_enum)]
        env: Env,

        /// 变量名
        #[arg(long, value_name = "KEY")]
        name: String,
    },
}

/// 环境标识。
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lower")]
pub enum Env {
    Dev,
    Prod,
}

impl Env {
    pub fn as_str(self) -> &'static str {
        match self {
            Env::Dev => "dev",
            Env::Prod => "prod",
        }
    }
}
