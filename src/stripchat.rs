use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose};
use chrono::Utc;
use log::{debug, error, info, warn};
use reqwest::{
    Client,
    cookie::{CookieStore, Jar},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
}

#[derive(Debug, Clone)]
enum CookieSource {
    ConfigFile,  // 来自配置文件
    CommandLine, // 来自命令行参数
    None,        // 没有cookie
}

#[derive(Debug, Clone, Deserialize)]
struct ApiResponse {
    model: ModelInfo, // 模特信息
    #[serde(rename = "isCamAvailable")]
    is_cam_available: bool, // 摄像头是否可用
    cam: Option<CamInfo>, // 摄像头信息
}

#[derive(Debug, Clone, Deserialize)]
struct ModelInfo {
    status: String, // 状态
}

#[derive(Debug, Clone, Deserialize)]
struct CamInfo {
    #[serde(rename = "isCamActive")]
    is_cam_active: bool, // 摄像头是否激活
    #[serde(rename = "streamName")]
    stream_name: String, // 流名称
}

#[derive(Debug, Clone, Deserialize)]
struct PlaylistVariant {
    url: String,            // 播放列表URL
    resolution: (u32, u32), // 分辨率 (宽度, 高度)
}

pub struct StripChatRecorder {
    config: Config,                               // 配置
    app_config: Arc<Mutex<AppConfig>>,            // 全局配置
    config_file_path: Option<PathBuf>,            // 配置文件路径
    cookie_source: CookieSource,                  // Cookie来源
    cookie_jar: Arc<Jar>,                         // Cookie存储
    client: Client,                               // HTTP客户端
    last_info: Option<ApiResponse>,               // 最后一次API响应
    psch: Option<String>,                         // PSCH参数
    pkey: Option<String>,                         // PKEY参数
    status: StreamStatus,                         // 流状态
    shutdown_rx: Option<broadcast::Receiver<()>>, // 关闭信号接收器
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
            let mut app_config = self.app_config.lock().await;
            app_config.cookies = Some(cookies.clone());

            // 如果有配置文件路径，保存到文件
            if let Some(config_path) = &self.config_file_path {
                if let Err(e) = app_config.save_to_file(config_path) {
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
        if let Some(cookie_header) = self.cookie_jar.cookies(&stripchat_url) {
            if let Ok(cookie_str) = cookie_header.to_str() {
                debug!(
                    "[{}] 从cookie jar提取到的cookies: {}",
                    self.config.username, cookie_str
                );
                return Ok(cookie_str.to_string());
            }
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

        loop {
            // 统一检查关闭信号
            if self.check_shutdown_signal() {
                return Ok(());
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
                    let app_config_clone = self.app_config.clone();
                    let config_file_path_clone = self.config_file_path.clone();
                    let cookie_source_clone = self.cookie_source.clone();
                    let username_clone = self.config.username.clone();
                    let shutdown_rx_clone = if let Some(ref shutdown_rx) = self.shutdown_rx {
                        Some(shutdown_rx.resubscribe())
                    } else {
                        None
                    };

                    tokio::spawn(async move {
                        let mut interval =
                            tokio::time::interval(tokio::time::Duration::from_secs(600)); // 10分钟

                        if let Some(mut shutdown_rx) = shutdown_rx_clone {
                            loop {
                                tokio::select! {
                                    _ = interval.tick() => {
                                        if let Err(e) =
                                            Self::refresh_cookies_and_save(&client_clone, &username_clone, &app_config_clone, &config_file_path_clone, &cookie_source_clone).await
                                        {
                                            debug!("[{}] 刷新 cookie 失败: {}", username_clone, e);
                                        } else {
                                            match cookie_source_clone {
                                                CookieSource::CommandLine => {
                                                    debug!("[{}] cookie 刷新成功（未保存到配置文件）", username_clone);
                                                }
                                                _ => {
                                                    debug!("[{}] cookie 刷新并保存成功", username_clone);
                                                }
                                            }
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
                                if let Err(e) = Self::refresh_cookies_and_save(
                                    &client_clone,
                                    &username_clone,
                                    &app_config_clone,
                                    &config_file_path_clone,
                                    &cookie_source_clone,
                                )
                                .await
                                {
                                    debug!("[{}] 刷新 cookie 失败: {}", username_clone, e);
                                } else {
                                    match cookie_source_clone {
                                        CookieSource::CommandLine => {
                                            debug!(
                                                "[{}] cookie 刷新成功（未保存到配置文件）",
                                                username_clone
                                            );
                                        }
                                        _ => {
                                            debug!("[{}] cookie 刷新并保存成功", username_clone);
                                        }
                                    }
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
                    } else {
                        if self
                            .interruptible_sleep(tokio::time::Duration::from_secs(
                                self.config.check_interval,
                            ))
                            .await
                        {
                            return Ok(());
                        }
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
            }
        }
    }

    /// 检查直播状态并记录结果
    async fn check_status_with_logging(
        &mut self,
        previous_status: &mut StreamStatus,
    ) -> Result<StreamStatus> {
        let url = format!(
            "https://stripchat.com/api/vr/v2/models/username/{}",
            self.config.username
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

        let status = match api_response.model.status.as_str() {
            "public" if api_response.is_cam_available => {
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
        let processor = move |content: &str| Self::m3u_decoder(content, &username);
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
        let master_url = format!(
            "https://edge-hls.doppiocdn.com/hls/{}/master/{}_auto.m3u8",
            stream_name, stream_name
        );

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

    /// 提取 MOUFLON 参数
    fn extract_mouflon_params(&mut self, content: &str) {
        if let Some(line) = content
            .lines()
            .find(|line| line.contains("#EXT-X-MOUFLON:"))
        {
            let parts: Vec<&str> = line.split(':').collect();
            if let [_, _, psch, pkey, ..] = parts.as_slice() {
                self.psch = Some(psch.to_string());
                self.pkey = Some(pkey.to_string());
                debug!("[{}] 提取 MOUFLON 参数", self.config.username);
            }
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

                // 如果可用，添加 MOUFLON 参数
                if let (Some(psch), Some(pkey)) = (&self.psch, &self.pkey) {
                    if url.contains('?') {
                        url = format!("{}&psch={}&pkey={}", url, psch, pkey);
                    } else {
                        url = format!("{}?psch={}&pkey={}", url, psch, pkey);
                    }
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
        let timestamp = Utc::now().format("%Y-%m-%d-%H-%M-%S");
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

    // M3U8 解密函数
    fn m3u_decoder(content: &str, username: &str) -> String {
        let mut decoded = Vec::new();
        let lines: Vec<&str> = content.lines().collect();
        let mut i = 0;

        debug!("[{}] M3U8 解码器开始处理 {} 行", username, lines.len());

        while i < lines.len() {
            let line = lines[i];

            if line.starts_with("#EXT-X-MOUFLON:FILE:") {
                let encrypted_data = &line[20..];
                debug!("[{}] 在索引 {} 发现 MOUFLON FILE 行: {}", username, i, line);

                match Self::decode_mouflon(encrypted_data, "Quean4cai9boJa5a") {
                    Ok(decrypted) => {
                        debug!("[{}] 解密成功: {}", username, decrypted);

                        // Process the next line if it exists
                        if i + 1 < lines.len() {
                            let original_line = lines[i + 1];
                            let next_line = original_line.replace("media.mp4", &decrypted);
                            debug!("[{}] 原始下一行: {}", username, original_line);
                            debug!("[{}] 转换后的下一行: {}", username, next_line);
                            decoded.push(next_line);
                            i += 2; // Skip both current line and next line
                            continue;
                        }
                    }
                    Err(e) => {
                        debug!("[{}] MOUFLON 解密失败: {}", username, e);
                    }
                }
            }

            decoded.push(line.to_string());
            i += 1;
        }

        debug!("[{}] M3U8 解码器完成处理 {} 行", username, decoded.len());
        decoded.join("\n")
    }

    /// 解码 MOUFLON 加密数据
    fn decode_mouflon(encrypted_b64: &str, key: &str) -> Result<String> {
        debug!(
            "尝试解码 MOUFLON: 长度={}, 数据={}",
            encrypted_b64.len(),
            encrypted_b64
        );

        // 如需要，正确添加 base64 填充
        let mut padded = encrypted_b64.to_string();
        while padded.len() % 4 != 0 {
            padded.push('=');
        }

        debug!("填充后的 base64: 长度={}, 数据={}", padded.len(), padded);
        let encrypted_data = general_purpose::STANDARD
            .decode(&padded)
            .map_err(|e| anyhow!("Base64 解码失败: {}", e))?;

        // 从密钥生成哈希
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        let hash_bytes = hasher.finalize();

        // 解密
        let mut decrypted_bytes = Vec::new();
        for (i, &cipher_byte) in encrypted_data.iter().enumerate() {
            let key_byte = hash_bytes[i % hash_bytes.len()];
            let decrypted_byte = cipher_byte ^ key_byte;
            decrypted_bytes.push(decrypted_byte);
        }

        String::from_utf8(decrypted_bytes).map_err(|e| anyhow!("UTF-8 解码错误: {}", e))
    }

    /// 刷新 cookies 并保存到配置
    async fn refresh_cookies_and_save(
        client: &Client,
        username: &str,
        app_config: &Arc<Mutex<AppConfig>>,
        config_file_path: &Option<PathBuf>,
        cookie_source: &CookieSource,
    ) -> Result<()> {
        let website_url = format!("https://stripchat.com/{}", username);
        debug!(
            "[{}] 通过访问以下地址刷新 cookie: {}",
            username, website_url
        );

        // 发送请求以刷新cookies
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
            // 提取新的cookies
            let mut new_cookies = Vec::new();

            // 从响应头中提取Set-Cookie
            for (name, value) in response.headers().iter() {
                if name.as_str().to_lowercase() == "set-cookie" {
                    if let Ok(cookie_str) = value.to_str() {
                        // 提取cookie的键值对（去掉额外的属性如path, domain等）
                        if let Some(cookie_part) = cookie_str.split(';').next() {
                            new_cookies.push(cookie_part.to_string());
                        }
                    }
                }
            }

            // 如果没有从Set-Cookie头获取到新cookies，尝试从现有的cookie jar中获取
            if new_cookies.is_empty() {
                // 创建一个新的请求来检查当前的cookie状态
                let test_request = client.head(&website_url).build()?;

                if let Some(cookie_header) = test_request.headers().get("cookie") {
                    if let Ok(cookie_str) = cookie_header.to_str() {
                        // 将整个cookie字符串作为一个条目
                        new_cookies.push(cookie_str.to_string());
                    }
                }
            }

            if !new_cookies.is_empty() {
                let cookies_string = new_cookies.join("; ");

                // 只有在非命令行cookie时才保存到配置文件
                match cookie_source {
                    CookieSource::CommandLine => {
                        debug!(
                            "[{}] cookie 刷新成功（来自命令行，不保存到配置文件）",
                            username
                        );
                    }
                    CookieSource::ConfigFile | CookieSource::None => {
                        // 更新AppConfig中的cookies
                        let mut app_config_guard = app_config.lock().await;
                        app_config_guard.cookies = Some(cookies_string);

                        // 如果有配置文件路径，保存到文件
                        if let Some(config_path) = config_file_path {
                            if let Err(e) = app_config_guard.save_to_file(config_path) {
                                debug!("[{}] 保存配置文件失败: {}", username, e);
                            } else {
                                debug!("[{}] 配置文件已更新: {}", username, config_path.display());
                            }
                        }

                        debug!("[{}] cookie 刷新并保存成功", username);
                    }
                }
            } else {
                debug!("[{}] 未获取到新的cookies", username);
            }
        } else {
            warn!("[{}] cookie 刷新失败: {}", username, response.status());
        }

        Ok(())
    }
}
