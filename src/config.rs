use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub usernames: Option<Vec<String>>, // 用户名列表
    pub output_dir: Option<String>,     // 输出目录
    pub resolution: Option<u32>,        // 视频分辨率
    pub check_interval: Option<u64>,    // 检查间隔
    pub debug: Option<bool>,            // 调试模式
    pub proxy: Option<String>,          // 代理地址
    pub proxy_username: Option<String>, // 代理用户名
    pub proxy_password: Option<String>, // 代理密码
    pub user_agent: Option<String>,     // 用户代理
    pub log_to_file: Option<bool>,      // 是否输出日志到文件
    pub log_file_path: Option<String>,  // 日志文件路径
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            usernames: Some(vec![]),
            output_dir: Some("downloads".to_string()),
            resolution: Some(1080),
            check_interval: Some(30),
            debug: Some(false),
            proxy: None,
            proxy_username: None,
            proxy_password: None,
            user_agent: Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36".to_string()),
            log_to_file: Some(true),
            log_file_path: None,
        }
    }
}

impl AppConfig {
    /// 从配置文件加载配置
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())
            .with_context(|| format!("无法读取配置文件: {}", path.as_ref().display()))?;

        let config: AppConfig = serde_json::from_str(&content)
            .with_context(|| format!("无法解析配置文件: {}", path.as_ref().display()))?;

        Ok(config)
    }

    /// 保存配置到文件
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = serde_json::to_string_pretty(self).context("无法序列化配置")?;

        std::fs::write(path.as_ref(), content)
            .with_context(|| format!("无法写入配置文件: {}", path.as_ref().display()))?;

        Ok(())
    }

    /// 获取默认配置文件路径
    pub fn get_default_config_path() -> PathBuf {
        // 尝试获取程序所在目录
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                return exe_dir.join("config.json");
            }
        }

        // 如果获取失败，使用当前工作目录
        PathBuf::from("config.json")
    }

    /// 合并命令行参数到配置中（命令行参数优先）
    pub fn merge_with_cli(&mut self, cli_args: &CliArgs) {
        if let Some(usernames_str) = &cli_args.usernames {
            let usernames: Vec<String> = usernames_str
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToString::to_string)
                .collect();
            if !usernames.is_empty() {
                self.usernames = Some(usernames);
            }
        }

        // 使用更简洁的Option赋值
        self.output_dir = cli_args.output_dir.clone().or(self.output_dir.take());
        self.resolution = cli_args.resolution.or(self.resolution);
        self.check_interval = cli_args.check_interval.or(self.check_interval);
        self.debug = cli_args.debug.or(self.debug);
        self.proxy = cli_args.proxy.clone().or(self.proxy.take());
        self.proxy_username = cli_args
            .proxy_username
            .clone()
            .or(self.proxy_username.take());
        self.proxy_password = cli_args
            .proxy_password
            .clone()
            .or(self.proxy_password.take());
        self.log_to_file = cli_args.log_to_file.or(self.log_to_file);
        self.log_file_path = cli_args.log_file_path.clone().or(self.log_file_path.take());
    }

    /// 获取最终配置值，如果字段为None则使用默认值
    pub fn get_usernames(&self) -> Result<Vec<String>> {
        self.usernames
            .as_ref()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("未指定用户名"))
    }

    pub fn get_output_dir(&self) -> String {
        self.output_dir
            .as_deref()
            .unwrap_or("downloads")
            .to_string()
    }

    pub fn get_resolution(&self) -> u32 {
        self.resolution.unwrap_or(1080)
    }

    pub fn get_check_interval(&self) -> u64 {
        self.check_interval.unwrap_or(30)
    }

    pub fn get_debug(&self) -> bool {
        self.debug.unwrap_or(false)
    }

    pub fn get_proxy(&self) -> Option<String> {
        self.proxy.clone()
    }

    pub fn get_proxy_username(&self) -> Option<String> {
        self.proxy_username.clone()
    }

    pub fn get_proxy_password(&self) -> Option<String> {
        self.proxy_password.clone()
    }

    pub fn get_log_to_file(&self) -> bool {
        self.log_to_file.unwrap_or(true)
    }

    pub fn get_log_file_path(&self) -> Option<String> {
        self.log_file_path.clone()
    }

    /// 生成默认的日志文件路径
    pub fn generate_default_log_path() -> PathBuf {
        let timestamp = chrono::Local::now().format("%Y-%m-%d-%H-%M-%S");
        let filename = format!("screc-{}.log", timestamp);

        // 尝试获取程序所在目录
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                return exe_dir.join("logs").join(filename);
            }
        }

        // 如果获取失败，使用当前工作目录的logs文件夹
        PathBuf::from("logs").join(filename)
    }

    #[allow(dead_code)]
    pub fn get_user_agent(&self) -> String {
        self.user_agent.as_deref().unwrap_or(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        ).to_string()
    }
}

/// 命令行参数结构
#[derive(Debug, Clone)]
pub struct CliArgs {
    #[allow(dead_code)]
    pub config_file: Option<String>, // 配置文件路径
    pub usernames: Option<String>,      // 用户名字符串
    pub output_dir: Option<String>,     // 输出目录
    pub resolution: Option<u32>,        // 视频分辨率
    pub check_interval: Option<u64>,    // 检查间隔
    pub debug: Option<bool>,            // 调试模式
    pub proxy: Option<String>,          // 代理地址
    pub proxy_username: Option<String>, // 代理用户名
    pub proxy_password: Option<String>, // 代理密码
    pub log_to_file: Option<bool>,      // 是否输出日志到文件
    pub log_file_path: Option<String>,  // 日志文件路径
}

#[derive(Debug, Clone)]
pub struct Config {
    pub username: String,               // 用户名
    pub output_dir: String,             // 输出目录
    pub resolution: u32,                // 视频分辨率
    pub check_interval: u64,            // 检查间隔
    pub proxy: Option<String>,          // 代理地址
    pub proxy_username: Option<String>, // 代理用户名
    pub proxy_password: Option<String>, // 代理密码
}

impl Config {
    pub fn user_agent() -> &'static str {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
}
