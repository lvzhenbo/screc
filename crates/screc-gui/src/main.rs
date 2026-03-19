// Release 构建默认作为 Windows GUI 程序（不弹出控制台窗口）
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod gui;
mod gui_logger;
pub mod shared_state;

use crate::shared_state::{ModelCommand, ModelStreamStatus, SharedGuiState};
use anyhow::{Context, Result};
use log::{debug, error, info, warn};
use screc_core::config::{AppConfig, Config};
use screc_core::stripchat::{RecorderCallback, StreamStatus, StripChatRecorder};
use screc_core::utils::{ProxyConfig, get_proxy_from_env};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{Mutex, broadcast};

/// 实现 RecorderCallback，将核心录制器的状态变化桥接到 GUI 状态
struct GuiRecorderCallback(SharedGuiState);

impl RecorderCallback for GuiRecorderCallback {
    fn on_status_change(&self, username: &str, status: &StreamStatus) {
        let gui_status = match status {
            StreamStatus::Public => ModelStreamStatus::Public,
            StreamStatus::Private => ModelStreamStatus::Private,
            StreamStatus::Offline => ModelStreamStatus::Offline,
            StreamStatus::LongOffline => ModelStreamStatus::LongOffline,
            StreamStatus::Error => ModelStreamStatus::Error,
            StreamStatus::Unknown => ModelStreamStatus::Unknown,
            StreamStatus::NotExist => ModelStreamStatus::NotExist,
            StreamStatus::Restricted => ModelStreamStatus::Restricted,
        };
        self.0.update_status(username, gui_status);
    }

    fn on_recording_start(&self, username: &str, file_path: &str) {
        self.0
            .set_recording(username, true, Some(file_path.to_string()));
    }

    fn on_recording_stop(&self, username: &str) {
        self.0.set_recording(username, false, None);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let config_path = AppConfig::get_default_config_path();
    let app_config = screc_core::load_config(&config_path);

    run_gui_mode(app_config, config_path).await
}

/// GUI 模式入口：只使用配置文件运行
async fn run_gui_mode(app_config: AppConfig, config_path: PathBuf) -> Result<()> {
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
        if let Some(file_dispatch) = screc_core::create_file_logger(&app_config) {
            dispatch = dispatch.chain(file_dispatch);
        }
    }

    // GUI 日志输出
    let gui_logger_dispatch = fern::Dispatch::new()
        .format(|out, message, _record| out.finish(format_args!("{}", message)))
        .chain(Box::new(crate::gui_logger::GuiLogger::new(gui_state.clone())) as Box<dyn log::Log>);
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

// ── 模特管理器 ────────────────────────────────────────────────────

/// 模特管理器：监听启停命令，动态创建/停止录制任务
async fn run_model_manager(
    mut cmd_rx: tokio::sync::mpsc::UnboundedReceiver<ModelCommand>,
    mut shutdown_rx: broadcast::Receiver<()>,
    shared_app_config: Arc<Mutex<AppConfig>>,
    shared_config_path: Option<PathBuf>,
    original_config_cookies: Option<String>,
    proxy_config: Option<ProxyConfig>,
    gui_state: SharedGuiState,
    initial_usernames: Vec<String>,
) {
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
                    Some(ModelCommand::Enable(username)) => {
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
                    Some(ModelCommand::Disable(username)) => {
                        if let Some((tx, _)) = active.remove(&username) {
                            info!("禁用用户 {} 的录制", username);
                            let _ = tx.send(());
                        }
                    }
                    Some(ModelCommand::Add(username, enabled)) => {
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
                    Some(ModelCommand::Remove(username)) => {
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
async fn spawn_gui_recorder_task(
    username: String,
    shared_app_config: &Arc<Mutex<AppConfig>>,
    shared_config_path: &Option<PathBuf>,
    original_config_cookies: &Option<String>,
    proxy_config: &Option<ProxyConfig>,
    shutdown_rx: broadcast::Receiver<()>,
    gui_state: SharedGuiState,
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
                recorder.set_callback(Arc::new(GuiRecorderCallback(gui_state)));
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
