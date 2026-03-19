use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use screc::config::{AppConfig, CliArgs};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "screc")]
#[command(about = "基于 Rust 的 StripChat 直播录制工具")]
#[command(version = env!("CARGO_PKG_VERSION"))]
struct Cli {
    /// 配置文件路径，默认为程序同目录下的 config.json
    #[arg(short, long)]
    config: Option<String>,

    /// 要录制的用户名，可以指定多个用户名，用逗号分隔 (例如: user1,user2,user3)
    #[arg(short, long)]
    usernames: Option<String>,

    /// 录制文件输出目录
    #[arg(short, long)]
    output_dir: Option<String>,

    /// 期望的视频分辨率高度 (例如: 720, 1080)
    #[arg(short, long)]
    resolution: Option<u32>,

    /// 离线时的检查间隔（秒）
    #[arg(long)]
    check_interval: Option<u64>,

    /// 启用调试日志
    #[arg(short, long)]
    debug: bool,

    /// HTTP 代理地址 (例如: http://127.0.0.1:8080, socks5://127.0.0.1:1080)
    #[arg(long)]
    proxy: Option<String>,

    /// 代理认证用户名
    #[arg(long)]
    proxy_username: Option<String>,

    /// 代理认证密码
    #[arg(long)]
    proxy_password: Option<String>,

    /// 是否输出日志到文件
    #[arg(long)]
    log_to_file: Option<bool>,

    /// 日志文件路径
    #[arg(long)]
    log_file: Option<String>,

    /// Cookie 字符串 (例如: "key1=value1; key2=value2")
    #[arg(long)]
    cookies: Option<String>,

    /// 生成默认配置文件，可选择指定配置文件名（默认为 config.json）
    #[arg(long, num_args = 0..=1, default_missing_value = "config.json")]
    generate_config: Option<String>,
}

impl From<&Cli> for CliArgs {
    fn from(cli: &Cli) -> Self {
        Self {
            config_file: cli.config.clone(),
            usernames: cli.usernames.clone(),
            output_dir: cli.output_dir.clone(),
            resolution: cli.resolution,
            check_interval: cli.check_interval,
            debug: cli.debug.then_some(true),
            proxy: cli.proxy.clone(),
            proxy_username: cli.proxy_username.clone(),
            proxy_password: cli.proxy_password.clone(),
            log_to_file: cli.log_to_file,
            log_file_path: cli.log_file.clone(),
            cookies: cli.cookies.clone(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // 生成配置文件
    if let Some(ref config_filename) = cli.generate_config {
        if cli.usernames.is_some()
            || cli.output_dir.is_some()
            || cli.resolution.is_some()
            || cli.check_interval.is_some()
            || cli.proxy.is_some()
        {
            eprintln!(
                "{}",
                "错误: 生成配置文件功能不能与其他录制相关参数一起使用".red()
            );
            eprintln!("{}", "请单独使用 --generate-config 参数".yellow());
            std::process::exit(1);
        }
        screc::generate_default_config(config_filename);
        return Ok(());
    }

    // 加载配置
    let config_path = cli
        .config
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_else(AppConfig::get_default_config_path);

    let mut app_config = screc::load_config(&config_path);

    // 合并命令行参数
    let cli_args = CliArgs::from(&cli);
    let has_cli_cookies = cli_args.cookies.is_some();
    let original_config_cookies = app_config.cookies.clone();
    app_config.merge_with_cli(&cli_args);

    screc::run_cli(
        app_config,
        config_path,
        has_cli_cookies,
        original_config_cookies,
    )
    .await
}
