use anyhow::{Context, Result};
use clap::Parser;
use colored::Colorize;
use log::{debug, error, info};
use screc_core::config::{AppConfig, CliArgs, Config};
use screc_core::stripchat::StripChatRecorder;
use screc_core::utils::{ProxyConfig, get_proxy_from_env};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{Mutex, broadcast};

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
        generate_default_config(config_filename);
        return Ok(());
    }

    // 加载配置
    let config_path = cli
        .config
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_else(AppConfig::get_default_config_path);

    let mut app_config = screc_core::load_config(&config_path);

    // 合并命令行参数
    let cli_args = CliArgs::from(&cli);
    let has_cli_cookies = cli_args.cookies.is_some();
    let original_config_cookies = app_config.cookies.clone();
    app_config.merge_with_cli(&cli_args);

    run_cli(
        app_config,
        config_path,
        has_cli_cookies,
        original_config_cookies,
    )
    .await
}

// ── CLI 专用逻辑 ──────────────────────────────────────────────────

/// CLI 模式入口：使用命令行参数运行
async fn run_cli(
    app_config: AppConfig,
    config_path: PathBuf,
    has_cli_cookies: bool,
    original_config_cookies: Option<String>,
) -> Result<()> {
    // 初始化日志
    let log_level = if app_config.get_debug() {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };

    let mut dispatch = fern::Dispatch::new().level(log_level);

    // CLI 模式：输出到控制台
    let console_config = fern::Dispatch::new()
        .format(|out, message, record| {
            let level_color = match record.level() {
                log::Level::Error => "ERROR".red().bold(),
                log::Level::Warn => "WARN".yellow().bold(),
                log::Level::Info => "INFO".green().bold(),
                log::Level::Debug => "DEBUG".blue().bold(),
                log::Level::Trace => "TRACE".purple().bold(),
            };

            out.finish(format_args!(
                "{} [{}] {}",
                chrono::Local::now()
                    .format("%Y-%m-%d %H:%M:%S%.3f")
                    .to_string()
                    .cyan(),
                level_color,
                message
            ))
        })
        .chain(std::io::stdout());
    dispatch = dispatch.chain(console_config);

    // 文件日志
    if app_config.get_log_to_file() {
        if let Some(file_dispatch) = screc_core::create_file_logger(&app_config) {
            dispatch = dispatch.chain(file_dispatch);
        }
    }

    dispatch.apply().context("无法初始化日志系统")?;

    let (mut tasks, shutdown_tx) = spawn_recording_tasks(
        app_config,
        config_path,
        has_cli_cookies,
        original_config_cookies,
    )
    .await?;

    // 等待所有任务完成或 Ctrl+C
    let mut all_tasks_completed = false;

    tokio::select! {
        _ = async {
            for task in &mut tasks {
                if let Err(e) = task.await {
                    error!("录制任务崩溃: {}", e);
                }
            }
            all_tasks_completed = true;
        } => {
            info!("所有录制任务已完成");
        }
        _ = tokio::signal::ctrl_c() => {
            info!("收到中断信号，正在关闭所有录制任务...");
            let _ = shutdown_tx.send(());
            info!("已发送关闭信号，等待任务完成...");
        }
    }

    if all_tasks_completed {
        return Ok(());
    }

    wait_for_shutdown(tasks).await;
    Ok(())
}

/// 生成默认配置文件
fn generate_default_config(config_filename: &str) {
    let config_path = PathBuf::from(config_filename);

    if config_path.exists() {
        println!(
            "{}",
            format!("警告: 配置文件 {} 已存在，将被覆盖", config_path.display()).yellow()
        );
    }

    match AppConfig::default().save_to_file(&config_path) {
        Ok(_) => {
            println!(
                "{}",
                format!("✓ 默认配置文件已生成: {}", config_path.display()).green()
            );
            println!(
                "{}",
                "配置文件生成完成，您可以编辑该文件来自定义录制设置".cyan()
            );
        }
        Err(e) => {
            eprintln!("{}", format!("错误: 生成配置文件失败: {}", e).red());
            std::process::exit(1);
        }
    }
}

async fn spawn_recording_tasks(
    app_config: AppConfig,
    config_path: PathBuf,
    has_cli_cookies: bool,
    original_config_cookies: Option<String>,
) -> Result<(Vec<tokio::task::JoinHandle<()>>, broadcast::Sender<()>)> {
    let usernames = app_config.get_usernames()?;

    if usernames.is_empty() {
        error!("请提供至少一个有效的用户名");
        std::process::exit(1);
    }

    if usernames.len() == 1 {
        info!("准备录制用户: {}", usernames[0]);
    } else {
        info!("准备录制 {} 个用户:", usernames.len());
        for (index, username) in usernames.iter().enumerate() {
            info!("  {}: {}", index + 1, username);
        }
    }

    // 处理代理配置
    let proxy_config = {
        let proxy_url = app_config.get_proxy().or_else(get_proxy_from_env);
        ProxyConfig::from_options(
            proxy_url,
            app_config.get_proxy_username(),
            app_config.get_proxy_password(),
        )
    };

    if let Some(ref proxy) = proxy_config {
        if let Err(e) = proxy.validate() {
            error!("无效的代理地址 '{}': {}", proxy.url, e);
            std::process::exit(1);
        }
        if proxy.username.is_some() && proxy.password.is_some() {
            debug!("使用认证代理: {}", proxy.url);
        } else {
            debug!("使用代理: {}", proxy.url);
        }
    }

    let mut tasks = Vec::new();
    let (shutdown_tx, _) = broadcast::channel(1);

    let shared_app_config = Arc::new(Mutex::new(app_config));
    let shared_config_path = if config_path.exists() {
        Some(config_path)
    } else {
        None
    };

    for username in usernames {
        let config = Config::from_app_config(
            &*shared_app_config.lock().await,
            username.clone(),
            proxy_config.as_ref().map(|p| p.url.clone()),
            proxy_config.as_ref().and_then(|p| p.username.clone()),
            proxy_config.as_ref().and_then(|p| p.password.clone()),
        );

        info!("为用户 {} 创建录制任务", username);

        let shutdown_rx = shutdown_tx.subscribe();
        let shared_app_config_clone = shared_app_config.clone();
        let shared_config_path_clone = shared_config_path.clone();
        let original_config_cookies_clone = original_config_cookies.clone();
        let recorder_task = tokio::spawn(async move {
            match StripChatRecorder::new(
                config,
                shared_app_config_clone,
                shared_config_path_clone,
                has_cli_cookies,
                original_config_cookies_clone,
            )
            .await
            {
                Ok(mut recorder) => {
                    recorder.set_shutdown_receiver(shutdown_rx);
                    debug!("开始为用户 {} 录制 StripChat 直播", username);
                    if let Err(e) = recorder.start_recording().await {
                        error!("用户 {} 录制失败: {}", username, e);
                    }
                }
                Err(e) => {
                    error!("为用户 {} 创建录制器失败: {}", username, e);
                }
            }
        });

        tasks.push(recorder_task);
    }

    Ok((tasks, shutdown_tx))
}

async fn wait_for_shutdown(tasks: Vec<tokio::task::JoinHandle<()>>) {
    let timeout = tokio::time::Duration::from_secs(60);
    let wait_for_tasks = async {
        for task in tasks {
            if let Err(e) = task.await {
                error!("录制任务崩溃: {}", e);
            }
        }
    };

    match tokio::time::timeout(timeout, wait_for_tasks).await {
        Ok(_) => {
            info!("所有录制任务已优雅关闭");
        }
        Err(_) => {
            error!("等待录制任务关闭超时，但已尽力完成清理");
        }
    }
}
