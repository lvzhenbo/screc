pub mod config;
pub mod downloader;
#[cfg(feature = "gui")]
pub mod gui;
#[cfg(feature = "gui")]
pub mod gui_logger;
#[cfg(feature = "gui")]
pub mod shared_state;
pub mod stripchat;
pub mod utils;

use anyhow::{Context, Result};
use colored::Colorize;
use config::{AppConfig, Config};
use log::{debug, error, info, warn};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use stripchat::StripChatRecorder;
use tokio::sync::{Mutex, broadcast};
use utils::{ProxyConfig, get_proxy_from_env};

/// 加载配置文件
pub fn load_config(config_path: &Path) -> AppConfig {
    if config_path.exists() {
        AppConfig::from_file(config_path)
            .inspect(|_| debug!("已加载配置文件: {}", config_path.display()))
            .inspect_err(|e| warn!("加载配置文件失败: {}，使用默认配置", e))
            .unwrap_or_default()
    } else {
        debug!("配置文件不存在，使用默认配置: {}", config_path.display());
        AppConfig::default()
    }
}

/// CLI 模式入口：使用命令行参数运行
pub async fn run_cli(
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
        if let Some(file_dispatch) = create_file_logger(&app_config) {
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

/// GUI 模式入口：只使用配置文件运行
#[cfg(feature = "gui")]
pub async fn run_gui_mode(app_config: AppConfig, config_path: PathBuf) -> Result<()> {
    let original_config_cookies = app_config.cookies.clone();

    // 初始化日志
    let log_level = if app_config.get_debug() {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };

    let gui_state = shared_state::SharedGuiState::new();
    gui_state.set_config_path(config_path.clone());

    // 创建模特启停命令通道
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
    gui_state.set_command_sender(cmd_tx);

    let mut dispatch = fern::Dispatch::new().level(log_level);

    // 文件日志
    if app_config.get_log_to_file() {
        if let Some(file_dispatch) = create_file_logger(&app_config) {
            dispatch = dispatch.chain(file_dispatch);
        }
    }

    // GUI 日志输出
    let gui_logger_dispatch = fern::Dispatch::new()
        .format(|out, message, _record| out.finish(format_args!("{}", message)))
        .chain(Box::new(gui_logger::GuiLogger::new(gui_state.clone())) as Box<dyn log::Log>);
    dispatch = dispatch.chain(gui_logger_dispatch);

    dispatch.apply().context("无法初始化日志系统")?;

    // 准备模特列表
    let all_entries = app_config.get_model_entries();
    let enabled_usernames = app_config.get_usernames().unwrap_or_default();

    if all_entries.is_empty() {
        warn!("配置中没有任何模特");
    } else {
        gui_state.init_models(&all_entries);
        if enabled_usernames.is_empty() {
            warn!("所有用户名均已禁用");
        } else {
            info!("准备录制 {} 个用户:", enabled_usernames.len());
            for (i, u) in enabled_usernames.iter().enumerate() {
                info!("  {}: {}", i + 1, u);
            }
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

    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
    let shared_app_config = Arc::new(Mutex::new(app_config));
    let shared_config_path = if config_path.exists() {
        Some(config_path)
    } else {
        None
    };

    // 启动模特管理器（负责动态启停录制任务）
    let manager_handle = tokio::spawn(run_model_manager(
        cmd_rx,
        shutdown_rx,
        shared_app_config,
        shared_config_path,
        original_config_cookies,
        proxy_config,
        gui_state.clone(),
        enabled_usernames,
    ));

    // 运行 GUI（阻塞主线程）
    gui::run_gui(gui_state);

    info!("GUI 已关闭，正在关闭所有录制任务...");
    let _ = shutdown_tx.send(());
    info!("已发送关闭信号，等待任务完成...");

    if let Err(e) = manager_handle.await {
        error!("模特管理任务崩溃: {}", e);
    }

    Ok(())
}

/// 生成默认配置文件
pub fn generate_default_config(config_filename: &str) {
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

// ── 内部辅助函数 ──────────────────────────────────────────────────

/// 创建文件日志 Dispatch
fn create_file_logger(app_config: &AppConfig) -> Option<fern::Dispatch> {
    let log_file_path = app_config.generate_log_path();

    if let Some(parent) = log_file_path.parent()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        eprintln!("警告: 无法创建日志文件目录 {}: {}", parent.display(), e);
        return None;
    }

    match std::fs::OpenOptions::new()
        .create(true)
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
            info!("日志文件: {}", log_file_path.display());
            Some(file_config)
        }
        Err(e) => {
            eprintln!("警告: 无法创建日志文件 {}: {}", log_file_path.display(), e);
            None
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

// ── GUI 模特管理器 ────────────────────────────────────────────────

/// 模特管理器：监听启停命令，动态创建/停止录制任务
#[cfg(feature = "gui")]
async fn run_model_manager(
    mut cmd_rx: tokio::sync::mpsc::UnboundedReceiver<shared_state::ModelCommand>,
    mut shutdown_rx: broadcast::Receiver<()>,
    shared_app_config: Arc<Mutex<AppConfig>>,
    shared_config_path: Option<PathBuf>,
    original_config_cookies: Option<String>,
    proxy_config: Option<ProxyConfig>,
    gui_state: shared_state::SharedGuiState,
    initial_usernames: Vec<String>,
) {
    use std::collections::HashMap;

    let mut active: HashMap<String, (broadcast::Sender<()>, tokio::task::JoinHandle<()>)> =
        HashMap::new();

    // 启动初始已启用的模特录制任务
    for username in initial_usernames {
        let (tx, rx) = broadcast::channel(1);
        let handle = spawn_gui_recorder_task(
            username.clone(),
            &shared_app_config,
            &shared_config_path,
            &original_config_cookies,
            &proxy_config,
            rx,
            gui_state.clone(),
        )
        .await;
        active.insert(username, (tx, handle));
    }

    // 事件循环：监听启停命令和全局关闭信号
    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(shared_state::ModelCommand::Enable(username)) => {
                        if active.contains_key(&username) {
                            continue;
                        }
                        info!("启用用户 {} 的录制", username);
                        let (tx, rx) = broadcast::channel(1);
                        let handle = spawn_gui_recorder_task(
                            username.clone(),
                            &shared_app_config,
                            &shared_config_path,
                            &original_config_cookies,
                            &proxy_config,
                            rx,
                            gui_state.clone(),
                        )
                        .await;
                        active.insert(username, (tx, handle));
                    }
                    Some(shared_state::ModelCommand::Disable(username)) => {
                        if let Some((tx, _)) = active.remove(&username) {
                            info!("禁用用户 {} 的录制", username);
                            let _ = tx.send(());
                        }
                    }
                    Some(shared_state::ModelCommand::Add(username, enabled)) => {
                        if enabled && !active.contains_key(&username) {
                            info!("新增并启用用户 {} 的录制", username);
                            let (tx, rx) = broadcast::channel(1);
                            let handle = spawn_gui_recorder_task(
                                username.clone(),
                                &shared_app_config,
                                &shared_config_path,
                                &original_config_cookies,
                                &proxy_config,
                                rx,
                                gui_state.clone(),
                            )
                            .await;
                            active.insert(username, (tx, handle));
                        }
                    }
                    Some(shared_state::ModelCommand::Remove(username)) => {
                        if let Some((tx, _)) = active.remove(&username) {
                            info!("删除用户 {}，停止录制", username);
                            let _ = tx.send(());
                        }
                    }
                    None => break,
                }
            }
            _ = shutdown_rx.recv() => {
                info!("收到全局关闭信号，停止所有录制任务...");
                let mut handles = Vec::new();
                for (_, (tx, handle)) in active.drain() {
                    let _ = tx.send(());
                    handles.push(handle);
                }
                let timeout = tokio::time::Duration::from_secs(60);
                let _ = tokio::time::timeout(timeout, async {
                    for handle in handles {
                        let _ = handle.await;
                    }
                }).await;
                break;
            }
        }
    }
}

/// 为 GUI 模式创建单个模特的录制任务
#[cfg(feature = "gui")]
async fn spawn_gui_recorder_task(
    username: String,
    shared_app_config: &Arc<Mutex<AppConfig>>,
    shared_config_path: &Option<PathBuf>,
    original_config_cookies: &Option<String>,
    proxy_config: &Option<ProxyConfig>,
    shutdown_rx: broadcast::Receiver<()>,
    gui_state: shared_state::SharedGuiState,
) -> tokio::task::JoinHandle<()> {
    let config = Config::from_app_config(
        &*shared_app_config.lock().await,
        username.clone(),
        proxy_config.as_ref().map(|p| p.url.clone()),
        proxy_config.as_ref().and_then(|p| p.username.clone()),
        proxy_config.as_ref().and_then(|p| p.password.clone()),
    );

    info!("为用户 {} 创建录制任务", username);

    let shared_app_config_clone = shared_app_config.clone();
    let shared_config_path_clone = shared_config_path.clone();
    let original_config_cookies_clone = original_config_cookies.clone();

    tokio::spawn(async move {
        match StripChatRecorder::new(
            config,
            shared_app_config_clone,
            shared_config_path_clone,
            false,
            original_config_cookies_clone,
        )
        .await
        {
            Ok(mut recorder) => {
                recorder.set_shutdown_receiver(shutdown_rx);
                recorder.set_gui_state(gui_state);
                debug!("开始为用户 {} 录制 StripChat 直播", username);
                if let Err(e) = recorder.start_recording().await {
                    error!("用户 {} 录制失败: {}", username, e);
                }
            }
            Err(e) => {
                error!("为用户 {} 创建录制器失败: {}", username, e);
            }
        }
    })
}

/// 等待所有任务关闭
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
