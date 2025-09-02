mod config;
mod downloader;
mod stripchat;
mod utils;

use anyhow::{Context, Result};
use clap::Parser;
use colored::Colorize;
use config::{AppConfig, CliArgs, Config};
use log::{error, info, warn};
use std::path::PathBuf;
use stripchat::StripChatRecorder;
use tokio::sync::broadcast;
use utils::{ProxyConfig, get_proxy_from_env};

#[derive(Parser)]
#[command(name = "screc")]
#[command(about = "基于 Rust 的 StripChat 直播录制工具")]
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

    /// 生成默认配置文件
    #[arg(long)]
    generate_config: bool,
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
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // 如果需要生成配置文件
    if cli.generate_config {
        let config_path = cli
            .config
            .as_deref()
            .map(PathBuf::from)
            .unwrap_or_else(AppConfig::get_default_config_path);

        AppConfig::default()
            .save_to_file(&config_path)
            .inspect(|_| info!("默认配置文件已生成: {}", config_path.display()))
            .inspect_err(|e| error!("生成配置文件失败: {}", e))?;

        return Ok(());
    }

    // 加载配置
    let config_path = cli
        .config
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_else(AppConfig::get_default_config_path);

    let mut app_config = if config_path.exists() {
        AppConfig::from_file(&config_path)
            .inspect(|_| info!("已加载配置文件: {}", config_path.display()))
            .inspect_err(|e| warn!("加载配置文件失败: {}，使用默认配置", e))
            .unwrap_or_default()
    } else {
        info!("配置文件不存在，使用默认配置: {}", config_path.display());
        AppConfig::default()
    };

    // 合并命令行参数
    let cli_args = CliArgs::from(&cli);
    app_config.merge_with_cli(&cli_args);

    // 初始化日志
    let log_level = if app_config.get_debug() {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };

    // 创建基础日志配置
    let mut dispatch = fern::Dispatch::new().level(log_level);

    // 控制台输出（带颜色）
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

    // 如果启用了文件日志，添加文件输出（无颜色）
    if app_config.get_log_to_file() {
        let log_file_path = if let Some(path) = app_config.get_log_file_path() {
            PathBuf::from(path)
        } else {
            AppConfig::generate_default_log_path()
        };

        // 确保日志文件目录存在
        if let Some(parent) = log_file_path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                eprintln!("警告: 无法创建日志文件目录 {}: {}", parent.display(), e);
            }
        }

        match std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open(&log_file_path)
        {
            Ok(log_file) => {
                let file_config = fern::Dispatch::new()
                    .format(|out, message, record| {
                        out.finish(format_args!(
                            "{} [{}] {}",
                            chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f"),
                            record.level(),
                            message
                        ))
                    })
                    .chain(log_file);

                dispatch = dispatch.chain(file_config);
                println!("日志文件: {}", log_file_path.display().to_string().green());
            }
            Err(e) => {
                eprintln!("警告: 无法创建日志文件 {}: {}", log_file_path.display(), e);
            }
        }
    }

    dispatch.apply().context("无法初始化日志系统")?;

    // 解析用户名
    let usernames = app_config.get_usernames()?;

    if usernames.is_empty() {
        error!("请提供至少一个有效的用户名");
        std::process::exit(1);
    }

    // 输出将要录制的用户信息
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

    // 验证代理配置
    if let Some(ref proxy) = proxy_config {
        if let Err(e) = proxy.validate() {
            error!("无效的代理地址 '{}': {}", proxy.url, e);
            std::process::exit(1);
        }

        // 根据是否有认证信息显示不同的日志
        if proxy.username.is_some() && proxy.password.is_some() {
            info!("使用认证代理: {}", proxy.url);
        } else {
            info!("使用代理: {}", proxy.url);
        }
    }

    // 为每个用户名创建录制任务
    let mut tasks = Vec::new();

    // 创建关闭信号
    let (shutdown_tx, _) = broadcast::channel(1);

    for username in usernames {
        let config = Config {
            username: username.clone(),
            output_dir: app_config.get_output_dir(),
            resolution: app_config.get_resolution(),
            check_interval: app_config.get_check_interval(),
            proxy: proxy_config.as_ref().map(|p| p.url.clone()),
            proxy_username: proxy_config.as_ref().and_then(|p| p.username.clone()),
            proxy_password: proxy_config.as_ref().and_then(|p| p.password.clone()),
        };

        info!("为用户 {} 创建录制任务", username);

        let shutdown_rx = shutdown_tx.subscribe();
        let recorder_task = tokio::spawn(async move {
            match StripChatRecorder::new(config).await {
                Ok(mut recorder) => {
                    recorder.set_shutdown_receiver(shutdown_rx);
                    info!("开始为用户 {} 录制 StripChat 直播", username);
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

    // 优雅处理 Ctrl+C
    let mut all_tasks_completed = false;

    tokio::select! {
        _ = async {
            // 等待所有任务完成
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

            // 向所有任务发送关闭信号
            let _ = shutdown_tx.send(());

            info!("已发送关闭信号，等待任务完成...");
        }
    }

    // 如果按下了 Ctrl+C，带超时等待任务完成
    if !all_tasks_completed {
        let timeout = tokio::time::Duration::from_secs(60); // 给60秒进行完成清理
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
    Ok(())
}
