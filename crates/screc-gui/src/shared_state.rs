use chrono::{DateTime, Local};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use screc_core::config::{AppConfig, ModelEntry};

/// GUI → 录制管理器的命令
pub enum ModelCommand {
    Enable(String),
    Disable(String),
    Add(String, bool),
    Remove(String),
}

/// 模特状态信息（用于 GUI 展示）
#[derive(Debug, Clone)]
pub struct ModelStatus {
    pub username: String,
    pub enabled: bool,
    pub status: ModelStreamStatus,
    pub is_recording: bool,
    pub recording_start: Option<DateTime<Local>>,
    pub last_check: Option<DateTime<Local>>,
    pub file_path: Option<String>,
}

/// 模特直播状态（映射自 StreamStatus）
#[derive(Debug, Clone, PartialEq)]
pub enum ModelStreamStatus {
    Public,
    Private,
    Offline,
    LongOffline,
    Error,
    Unknown,
    NotExist,
    Restricted,
}

impl ModelStreamStatus {
    pub fn label(&self) -> &str {
        match self {
            Self::Public => "在线",
            Self::Private => "私人秀",
            Self::Offline => "离线",
            Self::LongOffline => "长时间离线",
            Self::Error => "错误",
            Self::Unknown => "未知",
            Self::NotExist => "不存在",
            Self::Restricted => "受限",
        }
    }
}

/// 日志条目
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: DateTime<Local>,
    pub level: LogLevel,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum LogLevel {
    Info,
    Warn,
    Error,
    Debug,
}

impl LogLevel {
    pub fn label(&self) -> &str {
        match self {
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
            Self::Debug => "DEBUG",
        }
    }
}

/// 全局共享状态
#[derive(Clone)]
pub struct SharedGuiState {
    inner: Arc<Mutex<SharedGuiStateInner>>,
}

struct SharedGuiStateInner {
    models: Vec<ModelStatus>,
    logs: VecDeque<LogEntry>,
    max_logs: usize,
    config_path: Option<PathBuf>,
    command_tx: Option<tokio::sync::mpsc::UnboundedSender<ModelCommand>>,
}

impl SharedGuiState {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(SharedGuiStateInner {
                models: Vec::new(),
                logs: VecDeque::new(),
                max_logs: 100_000,
                config_path: None,
                command_tx: None,
            })),
        }
    }

    /// 设置配置文件路径（用于保存开关状态）
    pub fn set_config_path(&self, path: PathBuf) {
        self.inner.lock().unwrap().config_path = Some(path);
    }

    /// 设置命令发送器（用于通知管理器启停模特）
    pub fn set_command_sender(&self, tx: tokio::sync::mpsc::UnboundedSender<ModelCommand>) {
        self.inner.lock().unwrap().command_tx = Some(tx);
    }

    /// 设置 / 初始化模特列表
    pub fn init_models(&self, entries: &[ModelEntry]) {
        let mut inner = self.inner.lock().unwrap();
        inner.models = entries
            .iter()
            .map(|e| ModelStatus {
                username: e.username.clone(),
                enabled: e.enabled,
                status: ModelStreamStatus::Unknown,
                is_recording: false,
                recording_start: None,
                last_check: None,
                file_path: None,
            })
            .collect();
    }

    /// 更新某个模特的直播状态
    pub fn update_status(&self, username: &str, status: ModelStreamStatus) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(m) = inner.models.iter_mut().find(|m| m.username == username) {
            m.status = status;
            m.last_check = Some(Local::now());
        }
    }

    /// 标记模特开始录制
    pub fn set_recording(&self, username: &str, recording: bool, file_path: Option<String>) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(m) = inner.models.iter_mut().find(|m| m.username == username) {
            m.is_recording = recording;
            if recording {
                m.recording_start = Some(Local::now());
                m.file_path = file_path;
            } else {
                m.recording_start = None;
                m.file_path = None;
            }
        }
    }

    /// 追加一条日志
    pub fn push_log(&self, level: LogLevel, message: String) {
        let mut inner = self.inner.lock().unwrap();
        let entry = LogEntry {
            timestamp: Local::now(),
            level,
            message,
        };
        if inner.logs.len() >= inner.max_logs {
            inner.logs.pop_front();
        }
        inner.logs.push_back(entry);
    }

    /// 获取所有模特快照
    pub fn get_models(&self) -> Vec<ModelStatus> {
        self.inner.lock().unwrap().models.clone()
    }

    /// 切换模特启用状态，发送启停命令并同步到配置文件
    pub fn set_model_enabled(&self, username: &str, enabled: bool) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(m) = inner.models.iter_mut().find(|m| m.username == username) {
            m.enabled = enabled;
        }
        // 发送启停命令到管理器
        if let Some(ref tx) = inner.command_tx {
            let cmd = if enabled {
                ModelCommand::Enable(username.to_string())
            } else {
                ModelCommand::Disable(username.to_string())
            };
            let _ = tx.send(cmd);
        }
        // 同步到配置文件
        Self::sync_config_inner(&inner);
    }

    /// 获取所有日志快照
    pub fn get_logs(&self) -> Vec<LogEntry> {
        self.inner.lock().unwrap().logs.iter().cloned().collect()
    }

    /// 新增模特
    pub fn add_model(&self, username: &str, enabled: bool) {
        let mut inner = self.inner.lock().unwrap();
        // 检查是否已存在
        if inner.models.iter().any(|m| m.username == username) {
            return;
        }
        inner.models.push(ModelStatus {
            username: username.to_string(),
            enabled,
            status: ModelStreamStatus::Unknown,
            is_recording: false,
            recording_start: None,
            last_check: None,
            file_path: None,
        });
        // 发送命令到管理器
        if enabled {
            if let Some(ref tx) = inner.command_tx {
                let _ = tx.send(ModelCommand::Add(username.to_string(), true));
            }
        }
        Self::sync_config_inner(&inner);
    }

    /// 删除模特
    pub fn remove_model(&self, username: &str) {
        let mut inner = self.inner.lock().unwrap();
        // 发送移除命令（管理器会停止录制）
        if let Some(ref tx) = inner.command_tx {
            let _ = tx.send(ModelCommand::Remove(username.to_string()));
        }
        inner.models.retain(|m| m.username != username);
        Self::sync_config_inner(&inner);
    }

    /// 内部辅助：同步模特列表到配置文件
    fn sync_config_inner(inner: &SharedGuiStateInner) {
        if let Some(ref config_path) = inner.config_path {
            let entries: Vec<serde_json::Value> = inner
                .models
                .iter()
                .map(|m| {
                    serde_json::json!({
                        "username": m.username,
                        "enabled": m.enabled
                    })
                })
                .collect();
            let _ = AppConfig::update_field(
                config_path,
                "usernames",
                serde_json::Value::Array(entries),
            );
        }
    }
}
