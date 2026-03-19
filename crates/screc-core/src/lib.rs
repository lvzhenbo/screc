pub mod config;
pub mod downloader;
pub mod stripchat;
pub mod utils;

use config::AppConfig;
use log::{debug, info, warn};
use std::path::Path;

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

/// 创建文件日志 Dispatch
pub fn create_file_logger(app_config: &AppConfig) -> Option<fern::Dispatch> {
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
