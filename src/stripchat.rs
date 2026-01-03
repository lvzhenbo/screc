use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose};
use chrono::Local;
use log::{debug, error, info, warn};
use reqwest::{
    Client,
    cookie::{CookieStore, Jar},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{Mutex, broadcast};
use url::Url;

use crate::config::{AppConfig, Config};
use crate::downloader::HlsDownloader;
use crate::utils::create_client;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StreamStatus {
    Public,      // 公开
    Private,     // 私人
    Offline,     // 离线
    LongOffline, // 长时间离线
    Error,       // 错误
    Unknown,     // 未知
    NotExist,    // 不存在（模特已删除）
    Restricted,  // 受限（地理封锁）
}

#[derive(Debug, Clone)]
enum CookieSource {
    ConfigFile,  // 来自配置文件
    CommandLine, // 来自命令行参数
    None,        // 没有cookie
}

#[derive(Debug, Clone, Deserialize)]
struct ApiResponse {
    #[serde(rename = "user")]
    user: Option<UserInfoWrapper>, // 用户信息 (新API格式)
    model: Option<ModelInfo>, // 模特信息 (兼容旧格式)
    cam: Option<CamInfo>,     // 摄像头信息
    error: Option<String>,    // 错误信息
}

#[derive(Debug, Clone, Deserialize)]
struct UserInfoWrapper {
    user: ModelInfo, // 嵌套的用户信息
    #[serde(rename = "isGeoBanned")]
    is_geo_banned: Option<bool>, // 是否地理封锁
}

#[derive(Debug, Clone, Deserialize)]
struct ModelInfo {
    status: String, // 状态
    #[serde(rename = "isDeleted")]
    is_deleted: Option<bool>, // 是否已删除
}

#[derive(Debug, Clone, Deserialize)]
struct CamInfo {
    #[serde(rename = "isCamAvailable")]
    is_cam_available: bool, // 摄像头是否可用
    #[serde(rename = "isCamActive")]
    is_cam_active: bool, // 摄像头是否激活
    #[serde(rename = "streamName")]
    stream_name: String, // 流名称
    #[serde(rename = "modelToken")]
    model_token: Option<String>, // 模特令牌（用于私人秀等场景）
}

#[derive(Debug, Clone, Deserialize)]
struct PlaylistVariant {
    url: String,            // 播放列表URL
    resolution: (u32, u32), // 分辨率 (宽度, 高度)
}

pub struct StripChatRecorder {
    config: Config,                                          // 配置
    app_config: Arc<Mutex<AppConfig>>,                       // 全局配置
    config_file_path: Option<PathBuf>,                       // 配置文件路径
    cookie_source: CookieSource,                             // Cookie来源
    cookie_jar: Arc<Jar>,                                    // Cookie存储
    client: Client,                                          // HTTP客户端
    last_info: Option<ApiResponse>,                          // 最后一次API响应
    psch: Option<String>,                                    // PSCH参数
    pkey: Option<String>,                                    // PKEY参数
    status: StreamStatus,                                    // 流状态
    shutdown_rx: Option<broadcast::Receiver<()>>,            // 关闭信号接收器
    mouflon_keys: std::collections::HashMap<String, String>, // MOUFLON密钥缓存
}

impl StripChatRecorder {
    /// 创建新的 StripChat 录制器实例
    pub async fn new(
        config: Config,
        app_config: Arc<Mutex<AppConfig>>,
        config_file_path: Option<PathBuf>,
        cli_has_cookies: bool,
        original_config_cookies: Option<String>,
    ) -> Result<Self> {
        // 确定cookie来源
        let cookie_source = if cli_has_cookies {
            CookieSource::CommandLine
        } else if original_config_cookies.is_some() {
            CookieSource::ConfigFile
        } else {
            CookieSource::None
        };

        // 使用统一的代理客户端创建函数
        let (client, cookie_jar) = create_client(
            config.proxy.as_deref(),
            config.proxy_username.as_deref(),
            config.proxy_password.as_deref(),
            &config.user_agent,
            config.cookies.as_deref(),
        )?;

        // 初始化已知的 MOUFLON 密钥映射
        let mouflon_keys = std::collections::HashMap::from([
            (
                "Zeechoej4aleeshi".to_string(),
                "ubahjae7goPoodi6".to_string(),
            ),
            (
                "Ook7quaiNgiyuhai".to_string(),
                "8iPRUU0AnxoOSif9".to_string(),
            ),
        ]);

        let instance = Self {
            config,
            app_config: app_config.clone(),
            config_file_path,
            cookie_source,
            cookie_jar,
            client,
            last_info: None,
            psch: None,
            pkey: None,
            status: StreamStatus::Unknown,
            shutdown_rx: None,
            mouflon_keys,
        };

        // 根据cookie来源处理初始化
        match instance.cookie_source {
            CookieSource::None => {
                debug!(
                    "[{}] 没有配置cookie，将获取并保存到配置文件",
                    instance.config.username
                );
                instance.initialize_cookies().await?;
            }
            CookieSource::ConfigFile => {
                debug!("[{}] 使用配置文件中的cookies", instance.config.username);
            }
            CookieSource::CommandLine => {
                debug!("[{}] 使用命令行传入的cookies", instance.config.username);
            }
        }

        Ok(instance)
    }

    /// 生成随机uniq参数
    fn generate_uniq() -> String {
        use rand::Rng;
        let mut rng = rand::rng();
        let chars: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
        (0..16)
            .map(|_| {
                let idx = rng.random_range(0..chars.len());
                chars[idx] as char
            })
            .collect()
    }

    /// 检查错误是否可重试
    fn is_retryable_error(error: &anyhow::Error) -> bool {
        if let Some(reqwest_error) = error.downcast_ref::<reqwest::Error>() {
            // 网络错误通常可重试
            return reqwest_error.is_connect()
                || reqwest_error.is_timeout()
                || reqwest_error.is_request();
        }

        // 检查是否为暂时性HTTP错误
        let error_str = error.to_string().to_lowercase();
        error_str.contains("timeout")
            || error_str.contains("connection")
            || error_str.contains("temporarily")
            || error_str.contains("503")
            || error_str.contains("502")
            || error_str.contains("500")
    }

    /// 设置关闭信号接收器
    pub fn set_shutdown_receiver(&mut self, shutdown_rx: broadcast::Receiver<()>) {
        self.shutdown_rx = Some(shutdown_rx);
    }

    /// 检查是否收到关闭信号
    /// 返回 true 表示应该停止，false 表示继续运行
    fn check_shutdown_signal(&mut self) -> bool {
        if let Some(ref mut shutdown_rx) = self.shutdown_rx {
            match shutdown_rx.try_recv() {
                Ok(_) => {
                    info!("收到关闭信号，停止 {} 的录制循环", self.config.username);
                    true
                }
                Err(broadcast::error::TryRecvError::Empty) => {
                    // 没有关闭信号，继续运行
                    false
                }
                Err(broadcast::error::TryRecvError::Closed) => {
                    info!(
                        "关闭信号通道已关闭，停止 {} 的录制循环",
                        self.config.username
                    );
                    true
                }
                Err(broadcast::error::TryRecvError::Lagged(_)) => {
                    info!("错过了关闭信号，停止 {} 的录制循环", self.config.username);
                    true
                }
            }
        } else {
            false
        }
    }

    /// 可中断的等待函数
    /// 返回 true 表示收到关闭信号应该停止，false 表示等待完成可以继续
    async fn interruptible_sleep(&mut self, duration: tokio::time::Duration) -> bool {
        if let Some(ref mut shutdown_rx) = self.shutdown_rx {
            let mut shutdown_rx = shutdown_rx.resubscribe();
            tokio::select! {
                _ = tokio::time::sleep(duration) => {
                    // 等待完成，检查一次关闭信号
                    self.check_shutdown_signal()
                }
                _ = shutdown_rx.recv() => {
                    info!("等待期间收到关闭信号，停止 {} 的录制循环", self.config.username);
                    true
                }
            }
        } else {
            tokio::time::sleep(duration).await;
            false
        }
    }

    /// 将cookies保存到配置中
    async fn save_cookies_to_config(&self) -> Result<()> {
        // 从client的cookie存储中获取cookies
        let cookies = self.extract_cookies_from_client().await?;

        if !cookies.is_empty() {
            // 更新AppConfig中的cookies
            {
                let mut app_config = self.app_config.lock().await;
                app_config.cookies = Some(cookies.clone());
            }

            // 如果有配置文件路径，只更新cookies字段到文件
            if let Some(config_path) = &self.config_file_path {
                if let Err(e) =
                    AppConfig::update_field(config_path, "cookies", serde_json::json!(cookies))
                {
                    debug!("[{}] 保存配置文件失败: {}", self.config.username, e);
                } else {
                    debug!(
                        "[{}] 配置文件已更新: {}",
                        self.config.username,
                        config_path.display()
                    );
                }
            }

            debug!("[{}] cookies已更新到配置", self.config.username);
        }

        Ok(())
    }

    /// 从HTTP客户端提取cookies
    async fn extract_cookies_from_client(&self) -> Result<String> {
        let stripchat_url = "https://stripchat.com"
            .parse::<Url>()
            .map_err(|e| anyhow!("解析URL失败: {}", e))?;

        // 使用CookieStore trait方法从cookie jar中获取cookies
        if let Some(cookie_header) = self.cookie_jar.cookies(&stripchat_url)
            && let Ok(cookie_str) = cookie_header.to_str()
        {
            debug!(
                "[{}] 从cookie jar提取到的cookies: {}",
                self.config.username, cookie_str
            );
            return Ok(cookie_str.to_string());
        }

        debug!("[{}] cookie jar中没有找到cookies", self.config.username);
        Ok(String::new())
    }

    /// 通过访问主页初始化 cookies
    async fn initialize_cookies(&self) -> Result<()> {
        let website_url = format!("https://stripchat.com/{}", self.config.username);
        debug!(
            "[{}] 通过访问以下地址初始化 cookies: {}",
            self.config.username, website_url
        );

        let response = self
            .client
            .get(&website_url)
            .header(
                "Accept",
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            )
            .header("Accept-Language", "en-US,en;q=0.5")
            .header("DNT", "1")
            .header("Connection", "keep-alive")
            .header("Upgrade-Insecure-Requests", "1")
            .send()
            .await?;

        if response.status().is_success() {
            // 只有在没有配置cookie时才获取并保存cookies到配置中
            match self.cookie_source {
                CookieSource::None => {
                    if let Err(e) = self.save_cookies_to_config().await {
                        debug!("[{}] 保存cookies到配置失败: {}", self.config.username, e);
                    } else {
                        debug!("[{}] 成功获取并保存cookies到配置", self.config.username);
                    }
                }
                _ => {
                    debug!("[{}] 使用现有cookies，无需获取新的", self.config.username);
                }
            }
        } else {
            warn!(
                "[{}] 访问主页失败: {}",
                self.config.username,
                response.status()
            );
        }

        Ok(())
    }

    /// 开始录制循环
    pub async fn start_recording(&mut self) -> Result<()> {
        debug!("开始为用户 {} 录制循环", self.config.username);

        let mut offline_time = 0u64;
        let long_offline_timeout = 600u64; // 10分钟
        let mut previous_status = StreamStatus::Unknown;
        let mut last_cookie_save = std::time::Instant::now();
        let cookie_save_interval = std::time::Duration::from_secs(1800); // 30分钟保存一次cookies

        loop {
            // 统一检查关闭信号
            if self.check_shutdown_signal() {
                return Ok(());
            }

            // 定期保存cookies到配置文件
            if last_cookie_save.elapsed() > cookie_save_interval {
                if let Err(e) = self.save_current_cookies_to_config().await {
                    debug!("[{}] 定期保存cookies失败: {}", self.config.username, e);
                } else {
                    debug!("[{}] 定期保存cookies成功", self.config.username);
                }
                last_cookie_save = std::time::Instant::now();
            }

            // 检查状态并处理状态变化日志
            let status = match self.check_status_with_logging(&mut previous_status).await {
                Ok(status) => status,
                Err(e) => {
                    error!("[{}] 检查状态失败: {}", self.config.username, e);
                    StreamStatus::Error
                }
            };

            self.status = status.clone();

            match self.status {
                StreamStatus::Public => {
                    offline_time = 0; // 重置离线计数器

                    // 为长时间录制会话启动 cookie 刷新任务
                    let client_clone = self.client.clone();
                    let username_clone = self.config.username.clone();
                    let shutdown_rx_clone = self
                        .shutdown_rx
                        .as_ref()
                        .map(|shutdown_rx| shutdown_rx.resubscribe());

                    tokio::spawn(async move {
                        let mut interval =
                            tokio::time::interval(tokio::time::Duration::from_secs(1800)); // 30分钟

                        if let Some(mut shutdown_rx) = shutdown_rx_clone {
                            loop {
                                tokio::select! {
                                    _ = interval.tick() => {
                                        if let Err(e) =
                                            Self::refresh_cookies_only(&client_clone, &username_clone).await
                                        {
                                            debug!("[{}] 刷新 cookie 失败: {}", username_clone, e);
                                        } else {
                                            debug!("[{}] cookie 刷新成功", username_clone);
                                        }
                                    }
                                    _ = shutdown_rx.recv() => {
                                        debug!("[{}] cookie 刷新任务收到关闭信号", username_clone);
                                        break;
                                    }
                                }
                            }
                        } else {
                            // 没有关闭信号接收器的情况下，使用原有逻辑
                            loop {
                                interval.tick().await;
                                if let Err(e) =
                                    Self::refresh_cookies_only(&client_clone, &username_clone).await
                                {
                                    debug!("[{}] 刷新 cookie 失败: {}", username_clone, e);
                                } else {
                                    debug!("[{}] cookie 刷新成功", username_clone);
                                }
                            }
                        }
                    });

                    if let Err(e) = self.record_stream().await {
                        error!("[{}] 录制失败: {}", self.config.username, e);
                        self.status = StreamStatus::Error;
                        if self
                            .interruptible_sleep(tokio::time::Duration::from_secs(20))
                            .await
                        {
                            return Ok(());
                        }
                    }
                }
                StreamStatus::Private => {
                    offline_time = 0; // 重置离线计数器

                    // 检查是否有modelToken，如果有且不为空则尝试录制
                    if let Some(ref last_info) = self.last_info {
                        if let Some(ref cam) = last_info.cam {
                            if cam.model_token.as_ref().is_some_and(|t| !t.is_empty()) {
                                info!(
                                    "[{}] 私人秀检测到modelToken，尝试录制",
                                    self.config.username
                                );
                                if let Err(e) = self.record_stream().await {
                                    error!("[{}] 私人秀录制失败: {}", self.config.username, e);
                                }
                                // 录制完成后等待一段时间再检查
                                if self
                                    .interruptible_sleep(tokio::time::Duration::from_secs(
                                        self.config.check_interval,
                                    ))
                                    .await
                                {
                                    return Ok(());
                                }
                                continue;
                            }
                        }
                    }

                    // 没有modelToken，按原逻辑等待
                    if self
                        .interruptible_sleep(tokio::time::Duration::from_secs(5))
                        .await
                    {
                        return Ok(());
                    }
                }
                StreamStatus::Offline => {
                    offline_time += self.config.check_interval;
                    if offline_time > long_offline_timeout {
                        self.status = StreamStatus::LongOffline;
                        // 只有当状态实际变化时才记录日志
                        if std::mem::discriminant(&StreamStatus::LongOffline)
                            != std::mem::discriminant(&previous_status)
                        {
                            info!("[{}] 直播已离线一段时间", self.config.username);
                            previous_status = StreamStatus::LongOffline;
                        }
                        if self
                            .interruptible_sleep(tokio::time::Duration::from_secs(300))
                            .await
                        {
                            return Ok(());
                        }
                    } else if self
                        .interruptible_sleep(tokio::time::Duration::from_secs(
                            self.config.check_interval,
                        ))
                        .await
                    {
                        return Ok(());
                    }
                }
                StreamStatus::LongOffline => {
                    if self
                        .interruptible_sleep(tokio::time::Duration::from_secs(300))
                        .await
                    {
                        return Ok(());
                    }
                }
                StreamStatus::Error => {
                    if self
                        .interruptible_sleep(tokio::time::Duration::from_secs(20))
                        .await
                    {
                        return Ok(());
                    }
                }
                StreamStatus::Unknown => {
                    if self
                        .interruptible_sleep(tokio::time::Duration::from_secs(30))
                        .await
                    {
                        return Ok(());
                    }
                }
                StreamStatus::NotExist => {
                    // 模特已删除，停止监控
                    info!("[{}] 模特账号已删除，停止监控", self.config.username);
                    return Ok(());
                }
                StreamStatus::Restricted => {
                    // 地理封锁，每5分钟检查一次
                    if self
                        .interruptible_sleep(tokio::time::Duration::from_secs(300))
                        .await
                    {
                        return Ok(());
                    }
                }
            }
        }
    }

    /// 检查直播状态并记录结果
    async fn check_status_with_logging(
        &mut self,
        previous_status: &mut StreamStatus,
    ) -> Result<StreamStatus> {
        let mut retry_count = 0;
        const MAX_RETRIES: u32 = 3;

        loop {
            match self.check_status_internal(previous_status).await {
                Ok(status) => return Ok(status),
                Err(e) if retry_count < MAX_RETRIES && Self::is_retryable_error(&e) => {
                    retry_count += 1;
                    warn!(
                        "[{}] 状态检查失败 (尝试 {}/{}): {}",
                        self.config.username, retry_count, MAX_RETRIES, e
                    );

                    // 指数退避: 2^retry_count 秒
                    let delay = std::time::Duration::from_secs(2u64.pow(retry_count));
                    if self.interruptible_sleep(delay).await {
                        return Err(anyhow!("收到关闭信号，中断状态检查重试"));
                    }
                }
                Err(e) => {
                    if retry_count > 0 {
                        error!(
                            "[{}] 状态检查最终失败 (尝试了 {} 次): {}",
                            self.config.username,
                            retry_count + 1,
                            e
                        );
                    }
                    return Err(e);
                }
            }
        }
    }

    /// 内部状态检查实现
    async fn check_status_internal(
        &mut self,
        previous_status: &mut StreamStatus,
    ) -> Result<StreamStatus> {
        let uniq = Self::generate_uniq();
        let url = format!(
            "https://stripchat.com/api/front/v2/models/username/{}/cam?uniq={}",
            self.config.username, uniq
        );
        debug!("[{}] 检查状态: {}", self.config.username, url);

        // 可中断的网络请求
        let response = if let Some(ref mut shutdown_rx) = self.shutdown_rx {
            let mut shutdown_rx = shutdown_rx.resubscribe();
            tokio::select! {
                response = self.client.get(&url).send() => response?,
                _ = shutdown_rx.recv() => {
                    info!("[{}] 状态检查期间收到关闭信号", self.config.username);
                    return Err(anyhow!("收到关闭信号，中断状态检查"));
                }
            }
        } else {
            self.client.get(&url).send().await?
        };

        let api_response: ApiResponse = match response.status() {
            reqwest::StatusCode::NOT_FOUND => {
                let status = StreamStatus::Offline;
                info!("[{}] 状态: 离线 (用户不存在)", self.config.username);
                // 只在状态变化时更新 previous_status
                if std::mem::discriminant(&status) != std::mem::discriminant(previous_status) {
                    *previous_status = status.clone();
                }
                return Ok(status);
            }
            status if !status.is_success() => {
                // 检查是否为认证相关错误
                if status == reqwest::StatusCode::UNAUTHORIZED
                    || status == reqwest::StatusCode::FORBIDDEN
                {
                    warn!(
                        "[{}] 检测到认证错误 (HTTP {}), 尝试刷新cookies",
                        self.config.username, status
                    );

                    // 尝试刷新cookies
                    if let Err(e) =
                        Self::refresh_cookies_only(&self.client, &self.config.username).await
                    {
                        debug!("[{}] Cookie刷新失败: {}", self.config.username, e);
                    }

                    return Err(anyhow!("认证失败，已尝试刷新cookies: HTTP {}", status));
                }

                let error_status = StreamStatus::Error;
                error!("[{}] 状态: 错误 (HTTP {})", self.config.username, status);
                // 只在状态变化时更新 previous_status
                if std::mem::discriminant(&error_status) != std::mem::discriminant(previous_status)
                {
                    *previous_status = error_status.clone();
                }
                return Err(anyhow!("API 请求失败: {}", status));
            }
            _ => response.json().await?,
        };

        self.last_info = Some(api_response.clone());

        // 处理错误响应
        if let Some(error) = &api_response.error {
            let error_status = match error.as_str() {
                "Not Found" => StreamStatus::Offline,
                _ => StreamStatus::Error,
            };
            info!(
                "[{}] 状态: {} ({})",
                self.config.username,
                if matches!(error_status, StreamStatus::Offline) {
                    "离线"
                } else {
                    "错误"
                },
                error
            );
            if std::mem::discriminant(&error_status) != std::mem::discriminant(previous_status) {
                *previous_status = error_status.clone();
            }
            return Ok(error_status);
        }

        // 获取模型信息，优先使用新格式
        let model_info = api_response
            .user
            .as_ref()
            .map(|u| &u.user)
            .or(api_response.model.as_ref())
            .ok_or_else(|| anyhow!("API响应中缺少用户/模型信息"))?;

        // 检查是否已删除
        if model_info.is_deleted.unwrap_or(false) {
            let status = StreamStatus::NotExist;
            info!("[{}] 状态: 模特已删除", self.config.username);
            if std::mem::discriminant(&status) != std::mem::discriminant(previous_status) {
                *previous_status = status.clone();
            }
            return Ok(status);
        }

        // 检查是否地理封锁
        if api_response
            .user
            .as_ref()
            .and_then(|u| u.is_geo_banned)
            .unwrap_or(false)
        {
            let status = StreamStatus::Restricted;
            info!("[{}] 状态: 地理封锁", self.config.username);
            if std::mem::discriminant(&status) != std::mem::discriminant(previous_status) {
                *previous_status = status.clone();
            }
            return Ok(status);
        }

        let is_cam_available = api_response
            .cam
            .as_ref()
            .map(|c| c.is_cam_available)
            .unwrap_or(false);

        let status = match model_info.status.as_str() {
            "public" if is_cam_available => {
                let final_status = api_response
                    .cam
                    .as_ref()
                    .filter(|cam| cam.is_cam_active)
                    .map_or(StreamStatus::Offline, |_| StreamStatus::Public);

                // 每次都输出状态日志
                match final_status {
                    StreamStatus::Public => info!("[{}] 状态: 公开直播", self.config.username),
                    StreamStatus::Offline => info!("[{}] 状态: 离线", self.config.username),
                    _ => {}
                }
                // 只在状态变化时更新 previous_status
                if std::mem::discriminant(&final_status) != std::mem::discriminant(previous_status)
                {
                    *previous_status = final_status.clone();
                }
                final_status
            }
            "private" | "groupShow" | "p2p" | "virtualPrivate" | "p2pVoice" => {
                let status = StreamStatus::Private;
                info!("[{}] 状态: 私人秀", self.config.username);
                // 只在状态变化时更新 previous_status
                if std::mem::discriminant(&status) != std::mem::discriminant(previous_status) {
                    *previous_status = status.clone();
                }
                status
            }
            "off" | "idle" => {
                let status = StreamStatus::Offline;
                info!("[{}] 状态: 离线", self.config.username);
                // 只在状态变化时更新 previous_status
                if std::mem::discriminant(&status) != std::mem::discriminant(previous_status) {
                    *previous_status = status.clone();
                }
                status
            }
            unknown_status => {
                let status = StreamStatus::Unknown;
                warn!("[{}] 状态: 未知 ({})", self.config.username, unknown_status);
                // 只在状态变化时更新 previous_status
                if std::mem::discriminant(&status) != std::mem::discriminant(previous_status) {
                    *previous_status = status.clone();
                }
                status
            }
        };

        Ok(status)
    }

    /// 录制视频流
    async fn record_stream(&mut self) -> Result<()> {
        let video_url = self.get_video_url().await?;
        let output_path = self.generate_output_filename();

        info!("[{}] 录制到: {:?}", self.config.username, output_path);

        let mut downloader = HlsDownloader::new(self.client.clone(), self.config.username.clone());

        // 如果可用，将关闭接收器传递给下载器
        if let Some(ref shutdown_rx) = self.shutdown_rx {
            downloader = downloader.with_shutdown_receiver(shutdown_rx.resubscribe());
        }

        let username = self.config.username.clone();
        let mouflon_keys = self.mouflon_keys.clone();
        let processor = move |content: &str| {
            Self::m3u_decoder_with_dynamic_keys(content, &username, &mouflon_keys)
        };
        downloader
            .download_hls_stream(&video_url, &output_path, Some(&processor))
            .await?;

        Ok(())
    }

    /// 获取视频URL
    async fn get_video_url(&mut self) -> Result<String> {
        let variants = self.get_playlist_variants().await?;
        if variants.is_empty() {
            return Err(anyhow!("没有可用的视频版本"));
        }

        // 根据分辨率偏好选择最佳版本
        let selected_variant = self.select_best_variant(&variants)?;
        info!(
            "[{}] 选择的分辨率: {}x{}",
            self.config.username, selected_variant.resolution.0, selected_variant.resolution.1
        );

        Ok(selected_variant.url)
    }

    /// 获取播放列表版本
    async fn get_playlist_variants(&mut self) -> Result<Vec<PlaylistVariant>> {
        let Some(ref last_info) = self.last_info else {
            return Err(anyhow!("没有可用的直播信息"));
        };

        let Some(ref cam) = last_info.cam else {
            return Err(anyhow!("没有可用的摄像头信息"));
        };

        let stream_name = &cam.stream_name;
        let model_token = &cam.model_token;

        // 随机选择CDN主机 (模仿参考实现)
        use rand::prelude::IndexedRandom;
        let cdn_hosts = ["doppiocdn.org", "doppiocdn.com", "doppiocdn.net"];
        let selected_host = cdn_hosts
            .choose(&mut rand::rng())
            .unwrap_or(&"doppiocdn.com");

        // 构建基础URL并强制使用 psch=v2 和 pkey=Zeechoej4aleeshi（避免广告播放列表）
        // 参考: https://github.com/lossless1024/StreaMonitor/issues/310
        let mut master_url = Url::parse(&format!(
            "https://edge-hls.{}/hls/{}/master/{}_auto.m3u8",
            selected_host, stream_name, stream_name
        ))?;

        master_url
            .query_pairs_mut()
            .append_pair("psch", "v2")
            .append_pair("pkey", "Zeechoej4aleeshi");

        // 如果有modelToken且不为空，添加到URL参数中（参考JS的buildM3u8Url逻辑）
        if let Some(token) = model_token {
            if !token.is_empty() {
                master_url.query_pairs_mut().append_pair("aclAuth", token);
                debug!("[{}] 使用modelToken添加认证参数到URL", self.config.username);
            }
        }

        let master_url = master_url.to_string();

        debug!("[{}] 获取主播放列表: {}", self.config.username, master_url);

        // 可中断的网络请求
        let response = if let Some(ref mut shutdown_rx) = self.shutdown_rx {
            let mut shutdown_rx = shutdown_rx.resubscribe();
            tokio::select! {
                response = self.client.get(&master_url).send() => response?,
                _ = shutdown_rx.recv() => {
                    info!("[{}] 获取播放列表期间收到关闭信号", self.config.username);
                    return Err(anyhow!("收到关闭信号，中断播放列表获取"));
                }
            }
        } else {
            self.client.get(&master_url).send().await?
        };

        if !response.status().is_success() {
            return Err(anyhow!("获取主播放列表失败: {}", response.status()));
        }

        let content = response.text().await?;

        // 提取用于解密的 MOUFLON 参数
        self.extract_mouflon_params(&content);

        self.parse_master_playlist(&content, &master_url)
    }

    /// 提取 MOUFLON 参数 (修改：提取所有 PSCH 行中的第一个有效映射)
    fn extract_mouflon_params(&mut self, content: &str) {
        let mut found_psch = None;
        let mut found_pkey = None;

        // 遍历所有行查找 MOUFLON 行
        // 优先使用我们有密钥映射的 pkey
        for line in content.lines() {
            if line.starts_with("#EXT-X-MOUFLON:PSCH:") {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 4 {
                    let psch = parts[2].to_string();
                    let pkey = parts[3].to_string();

                    // 如果我们有这个 pkey 的密钥映射，优先使用它
                    if self.mouflon_keys.contains_key(&pkey) {
                        debug!("[{}] 找到有密钥映射的 pkey: {}", self.config.username, pkey);
                        found_psch = Some(psch);
                        found_pkey = Some(pkey);
                        break; // 找到有映射的就停止
                    }

                    // 否则保存第一个找到的（作为备用）
                    if found_psch.is_none() {
                        found_psch = Some(psch);
                        found_pkey = Some(pkey);
                    }
                }
            }
        }

        // Assign the found values
        self.psch = found_psch;
        self.pkey = found_pkey.clone();

        if self.psch.is_some() && self.pkey.is_some() {
            let pkey = found_pkey.as_ref().unwrap();
            if self.mouflon_keys.contains_key(pkey) {
                debug!(
                    "[{}] 提取 MOUFLON 参数: pkey={} (有密钥映射)",
                    self.config.username, pkey
                );
            } else {
                debug!(
                    "[{}] 提取 MOUFLON 参数: pkey={} (无密钥映射，可能解密失败)",
                    self.config.username, pkey
                );
            }
        } else {
            debug!("[{}] 未在内容中找到 MOUFLON 参数", self.config.username);
        }
    }

    /// 解析主播放列表
    fn parse_master_playlist(&self, content: &str, base_url: &str) -> Result<Vec<PlaylistVariant>> {
        let playlist = m3u8_rs::parse_playlist_res(content.as_bytes())
            .map_err(|e| anyhow!("解析主播放列表失败: {:?}", e))?;

        let mut variants = Vec::new();

        if let m3u8_rs::Playlist::MasterPlaylist(master_playlist) = playlist {
            for stream in &master_playlist.variants {
                let resolution = if let Some(res) = &stream.resolution {
                    (res.width as u32, res.height as u32)
                } else {
                    (0, 0)
                };

                let mut url = if stream.uri.starts_with("http") {
                    stream.uri.clone()
                } else {
                    let base = url::Url::parse(base_url)?;
                    base.join(&stream.uri)?.to_string()
                };

                // 强制使用 Zeechoej4aleeshi 密钥（避免服务器返回其他密钥的加密内容）
                if url.contains('?') {
                    url = format!("{}&psch=v2&pkey=Zeechoej4aleeshi", url);
                } else {
                    url = format!("{}?psch=v2&pkey=Zeechoej4aleeshi", url);
                }

                variants.push(PlaylistVariant { url, resolution });
            }
        }

        Ok(variants)
    }

    /// 选择最佳播放列表版本
    fn select_best_variant(&self, variants: &[PlaylistVariant]) -> Result<PlaylistVariant> {
        if variants.is_empty() {
            return Err(anyhow!("没有可用的版本"));
        }

        // 计算分辨率差异
        let target_height = self.config.resolution;
        let mut variants_with_diff: Vec<(PlaylistVariant, i32)> = variants
            .iter()
            .map(|variant| {
                let (width, height) = variant.resolution;
                // 对于竖屏视频使用较小的尺寸，对于横屏使用高度
                let resolution_diff = if width < height {
                    width as i32 - target_height as i32
                } else {
                    height as i32 - target_height as i32
                };
                (variant.clone(), resolution_diff)
            })
            .collect();

        // 按绝对差值排序（最接近的匹配在前）
        variants_with_diff.sort_by_key(|(_, diff)| diff.abs());

        // 根据偏好选择（为简化现在选择"最接近的"）
        let (selected_variant, diff) = &variants_with_diff[0];

        if selected_variant.resolution.1 != 0 {
            info!(
                "[{}] 选择 {}x{} 分辨率 (差异: {})",
                self.config.username,
                selected_variant.resolution.0,
                selected_variant.resolution.1,
                diff
            );
        }

        Ok(selected_variant.clone())
    }

    /// 生成输出文件名
    fn generate_output_filename(&self) -> PathBuf {
        let timestamp = Local::now().format("%Y-%m-%d-%H-%M-%S");
        let filename = format!("{}-{}.mp4", self.config.username, timestamp);

        let mut path = PathBuf::from(&self.config.output_dir);
        path.push(&self.config.username);

        // 如果不存在则创建目录
        if let Err(e) = std::fs::create_dir_all(&path) {
            error!("[{}] 创建输出目录失败: {}", self.config.username, e);
        }

        path.push(filename);
        path
    }

    // M3U8 解密函数 - 使用动态密钥提取
    fn m3u_decoder_with_dynamic_keys(
        content: &str,
        username: &str,
        mouflon_keys: &HashMap<String, String>,
    ) -> String {
        debug!("[{}] M3U8 解码器开始处理", username);

        // 使用改进的提取函数，直接获取解密密钥
        let (_psch, _pkey, decryption_key) =
            Self::extract_mouflon_from_m3u_with_key(content, mouflon_keys);

        let decryption_key = match decryption_key {
            Some(key) => key,
            None => {
                debug!(
                    "[{}] 未发现MOUFLON参数或无法获取解密密钥，返回原始内容",
                    username
                );
                return content.to_string();
            }
        };

        let mut decoded = Vec::new();
        let lines: Vec<&str> = content.lines().collect();
        let mut i = 0;
        let mut last_decoded_uri: Option<String> = None;

        while i < lines.len() {
            let line = lines[i];

            if let Some(uri_line) = line.strip_prefix("#EXT-X-MOUFLON:URI:") {
                if let Some(encoded_part) = uri_line.rsplit('_').nth(1) {
                    match Self::decode_mouflon(encoded_part, &decryption_key) {
                        Ok(decoded_part) => {
                            last_decoded_uri = Some(uri_line.replace(encoded_part, &decoded_part));
                            debug!(
                                "[{}] 成功解码 MOUFLON URI (行 {}): {}",
                                username,
                                i,
                                last_decoded_uri.as_ref().unwrap()
                            );
                        }
                        Err(e) => {
                            debug!("[{}] MOUFLON URI 解密失败 (行 {}): {}", username, i, e);
                            last_decoded_uri = None;
                        }
                    }
                } else {
                    debug!(
                        "[{}] MOUFLON URI 行格式异常 (行 {}): {}",
                        username, i, uri_line
                    );
                    last_decoded_uri = None;
                }

                i += 1;
                continue;
            }

            if let Some(encrypted_data) = line.strip_prefix("#EXT-X-MOUFLON:FILE:") {
                debug!("[{}] 在索引 {} 发现旧版 MOUFLON FILE 行", username, i);

                match Self::decode_mouflon(encrypted_data, &decryption_key) {
                    Ok(decrypted) => {
                        debug!("[{}] 解密成功: {}", username, decrypted);

                        if i + 1 < lines.len() {
                            let original_line = lines[i + 1];
                            let next_line = original_line.replace("media.mp4", &decrypted);
                            decoded.push(next_line);
                            i += 2;
                            continue;
                        }
                    }
                    Err(e) => {
                        debug!("[{}] MOUFLON 解密失败: {}", username, e);
                    }
                }
            }

            if line.ends_with("media.mp4") {
                if let Some(uri) = last_decoded_uri.take() {
                    decoded.push(uri);
                    i += 1;
                    continue;
                }
            }

            decoded.push(line.to_string());
            i += 1;
        }

        debug!("[{}] M3U8 解码器完成处理", username);
        decoded.join("\n")
    }

    /// 提取MOUFLON参数 - 改进版，支持多个MOUFLON头并返回解密密钥
    ///
    /// 重要说明：pkey 不是解密密钥，而是密钥的 ID！
    /// 需要通过 mouflon_keys 映射查找实际的解密密钥。
    /// 例如：pkey="Zeechoej4aleeshi" -> actual_key="ubahjae7goPoodi6"
    fn extract_mouflon_from_m3u_with_key(
        content: &str,
        mouflon_keys: &HashMap<String, String>,
    ) -> (Option<String>, Option<String>, Option<String>) {
        let needle = "#EXT-X-MOUFLON:PSCH:";
        let mut start = 0;

        // 遍历内容查找所有MOUFLON PSCH头
        while let Some(pos) = content[start..].find(needle) {
            let mouflon_start = start + pos;
            if let Some(line_end) = content[mouflon_start..].find('\n') {
                let line = &content[mouflon_start..mouflon_start + line_end];
                // 格式: #EXT-X-MOUFLON:PSCH:v1:Zeechoej4aleeshi
                // parts[0] = "#EXT-X-MOUFLON"
                // parts[1] = "PSCH"
                // parts[2] = "v1" (scheme)
                // parts[3] = "Zeechoej4aleeshi" (key ID, 不是实际密钥!)
                let parts: Vec<&str> = line.split(':').collect();

                if parts.len() >= 4 {
                    let psch = parts[2].to_string();
                    let pkey = parts[3].to_string();

                    // 从映射中查找实际的解密密钥
                    // pkey 是密钥 ID，需要查找对应的实际密钥
                    let decryption_key = mouflon_keys.get(&pkey).cloned().unwrap_or_else(|| {
                        // 如果映射中没有找到，记录警告并尝试使用 pkey 本身
                        // （这可能不会工作，但至少可以继续运行）
                        debug!(
                            "未在密钥映射中找到 pkey '{}' 的实际密钥，尝试使用 pkey 本身",
                            pkey
                        );
                        pkey.clone()
                    });

                    debug!(
                        "MOUFLON: psch={}, pkey={}, decryption_key={}",
                        psch, pkey, decryption_key
                    );

                    return (Some(psch), Some(pkey), Some(decryption_key));
                }
            }
            start = mouflon_start + needle.len();
        }

        (None, None, None)
    }

    /// 解码 MOUFLON 加密数据
    fn decode_mouflon(encrypted_b64: &str, key: &str) -> Result<String> {
        fn decode_inner(encrypted_b64: &str, key: &str, reverse_first: bool) -> Result<String> {
            let mut working: String = if reverse_first {
                encrypted_b64.chars().rev().collect()
            } else {
                encrypted_b64.to_string()
            };

            while working.len() % 4 != 0 {
                working.push('=');
            }

            let encrypted_data = general_purpose::STANDARD
                .decode(working.as_bytes())
                .map_err(|e| anyhow!("Base64 解码失败: {}", e))?;

            let mut hasher = Sha256::new();
            hasher.update(key.as_bytes());
            let hash_bytes = hasher.finalize();

            let decrypted_bytes: Vec<u8> = encrypted_data
                .iter()
                .zip(hash_bytes.iter().cycle())
                .map(|(&cipher_byte, &key_byte)| cipher_byte ^ key_byte)
                .collect();

            String::from_utf8(decrypted_bytes).map_err(|e| anyhow!("UTF-8 解码错误: {}", e))
        }

        debug!(
            "尝试解码 MOUFLON: 长度={}, 数据={}",
            encrypted_b64.len(),
            encrypted_b64
        );

        decode_inner(encrypted_b64, key, true).or_else(|err| {
            debug!("MOUFLON 反向解码失败，尝试旧版算法: {}", err);
            decode_inner(encrypted_b64, key, false)
        })
    }

    /// 刷新 cookies（仅访问网站刷新，不保存到配置）
    async fn refresh_cookies_only(client: &Client, username: &str) -> Result<()> {
        let website_url = format!("https://stripchat.com/{}", username);
        debug!(
            "[{}] 使用现有cookies访问以下地址刷新: {}",
            username, website_url
        );

        // 发送带有现有cookies的请求以刷新cookies
        // client会自动使用之前设置的cookie jar中的cookies
        let response = client
            .get(&website_url)
            .header(
                "Accept",
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            )
            .header("Accept-Language", "en-US,en;q=0.5")
            .header("DNT", "1")
            .header("Connection", "keep-alive")
            .header("Upgrade-Insecure-Requests", "1")
            .send()
            .await?;

        if response.status().is_success() {
            // 检查服务器是否返回了新的Set-Cookie头
            let set_cookie_headers: Vec<_> = response
                .headers()
                .get_all("set-cookie")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .collect();

            if !set_cookie_headers.is_empty() {
                debug!(
                    "[{}] 服务器返回了 {} 个新的cookie设置",
                    username,
                    set_cookie_headers.len()
                );
                debug!("[{}] cookies已自动更新到cookie jar", username);
            } else {
                debug!(
                    "[{}] 服务器没有返回新的Set-Cookie头，现有cookies仍然有效",
                    username
                );
            }
        } else {
            warn!("[{}] cookie 刷新请求失败: {}", username, response.status());
        }

        Ok(())
    }

    /// 保存当前cookie jar中的cookies到配置文件
    async fn save_current_cookies_to_config(&self) -> Result<()> {
        // 只有在非命令行cookie时才保存到配置文件
        match self.cookie_source {
            CookieSource::CommandLine => {
                debug!(
                    "[{}] 来自命令行的cookies，不保存到配置文件",
                    self.config.username
                );
                return Ok(());
            }
            CookieSource::ConfigFile | CookieSource::None => {
                // 从cookie jar提取cookies
                if let Ok(cookies) = self.extract_cookies_from_client().await
                    && !cookies.is_empty()
                {
                    // 更新AppConfig中的cookies
                    {
                        let mut app_config = self.app_config.lock().await;
                        app_config.cookies = Some(cookies.clone());
                    }

                    // 如果有配置文件路径，只更新cookies字段到文件
                    if let Some(config_path) = &self.config_file_path {
                        if let Err(e) = AppConfig::update_field(
                            config_path,
                            "cookies",
                            serde_json::json!(cookies),
                        ) {
                            debug!("[{}] 保存配置文件失败: {}", self.config.username, e);
                        } else {
                            debug!(
                                "[{}] 配置文件已更新: {}",
                                self.config.username,
                                config_path.display()
                            );
                        }
                    }

                    debug!("[{}] cookies已保存到配置", self.config.username);
                }
            }
        }

        Ok(())
    }
}
