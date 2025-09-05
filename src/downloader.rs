use anyhow::{Result, anyhow};
use log::{debug, error, info};
use reqwest::Client;
use std::collections::HashSet;
use std::path::Path;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::sync::broadcast;
use url::Url;

pub struct HlsDownloader {
    client: Client,                               // HTTP客户端
    downloaded_segments: HashSet<String>,         // 已下载的分片集合
    init_segment_downloaded: bool,                // 是否已下载初始化分片
    shutdown_rx: Option<broadcast::Receiver<()>>, // 关闭信号接收器
    username: String,                             // 用户名
    total_processed_segments: usize,              // 已处理的分片总数
}

impl HlsDownloader {
    /// 创建新的 HLS 下载器
    pub fn new(client: Client, username: String) -> Self {
        Self {
            client,
            downloaded_segments: HashSet::new(),
            init_segment_downloaded: false,
            shutdown_rx: None,
            username,
            total_processed_segments: 0,
        }
    }

    /// 添加关闭信号接收器
    pub fn with_shutdown_receiver(mut self, shutdown_rx: broadcast::Receiver<()>) -> Self {
        self.shutdown_rx = Some(shutdown_rx);
        self
    }

    /// 检查是否收到关闭信号
    /// 返回 true 表示应该停止，false 表示继续运行
    fn check_shutdown_signal(&mut self) -> bool {
        if let Some(ref mut shutdown_rx) = self.shutdown_rx {
            match shutdown_rx.try_recv() {
                Ok(_) => {
                    info!("[{}] 下载器收到关闭信号，停止下载", self.username);
                    true
                }
                Err(broadcast::error::TryRecvError::Empty) => {
                    // 没有关闭信号，继续运行
                    false
                }
                Err(broadcast::error::TryRecvError::Closed) => {
                    info!("[{}] 下载器关闭信号通道已关闭，停止下载", self.username);
                    true
                }
                Err(broadcast::error::TryRecvError::Lagged(_)) => {
                    info!("[{}] 下载器错过了关闭信号，停止下载", self.username);
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
                    info!("[{}] 下载器等待期间收到关闭信号，停止下载", self.username);
                    true
                }
            }
        } else {
            tokio::time::sleep(duration).await;
            false
        }
    }

    /// 下载 HLS 流
    pub async fn download_hls_stream<F>(
        &mut self,
        playlist_url: &str,
        output_path: &Path,
        m3u_processor: Option<&F>,
    ) -> Result<()>
    where
        F: Fn(&str) -> String,
    {
        debug!("[{}] 开始 HLS 下载到: {:?}", self.username, output_path);

        // 为原始 MP4 分片创建临时文件（fMP4）
        let temp_path = output_path.with_extension("tmp.mp4");
        let mut output_file = File::create(&temp_path).await?;
        let mut has_downloaded_content = false; // 跟踪是否实际下载了内容

        let mut consecutive_empty_playlists = 0;
        const MAX_EMPTY_PLAYLISTS: u32 = 10; // 从3增加到10以提高稳定性
        let mut dynamic_wait_time; // 基于分片目标持续时间的动态等待时间

        let download_result = if let Some(ref mut shutdown_rx) = self.shutdown_rx {
            let mut shutdown_rx = shutdown_rx.resubscribe();

            loop {
                tokio::select! {
                    result = self.download_playlist_segments(playlist_url, &mut output_file, m3u_processor) => {
                        match result {
                            Ok((has_new_content, target_duration)) => {
                                // 基于分片目标持续时间更新动态等待时间
                                dynamic_wait_time = if target_duration <= 2 {
                                    1 // 对于短分片，每1秒检查一次
                                } else if target_duration <= 6 {
                                    target_duration / 2 // 对于中等分片，以一半持续时间检查
                                } else {
                                    3 // 对于长分片，每3秒检查一次
                                };

                                if has_new_content {
                                    has_downloaded_content = true; // 标记已下载内容
                                    consecutive_empty_playlists = 0;
                                } else {
                                    consecutive_empty_playlists += 1;
                                    debug!("[{}] 播放列表中没有新分片 ({}/{})", self.username, consecutive_empty_playlists, MAX_EMPTY_PLAYLISTS);
                                    if consecutive_empty_playlists >= MAX_EMPTY_PLAYLISTS {
                                        info!(
                                            "[{}] 连续 {} 次未发现新分片，直播可能已结束",
                                            self.username, MAX_EMPTY_PLAYLISTS
                                        );
                                        break Ok(());
                                    }
                                    // 基于分片目标持续时间等待
                                    debug!("[{}] 等待 {} 秒后重新检查播放列表", self.username, dynamic_wait_time);
                                    if self.interruptible_sleep(tokio::time::Duration::from_secs(dynamic_wait_time)).await {
                                        break Ok(());
                                    }
                                }
                            }
                            Err(e) => {
                                error!("[{}] 下载分片时出错: {}", self.username, e);
                                // 出错时不要立即放弃，等待并重试
                                if self.interruptible_sleep(tokio::time::Duration::from_secs(3)).await {
                                    break Ok(());
                                }
                                consecutive_empty_playlists += 1;
                                if consecutive_empty_playlists >= MAX_EMPTY_PLAYLISTS {
                                    break Err(e);
                                }
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        info!("[{}] 收到关闭信号，停止下载新分片", self.username);
                        break Ok(());
                    }
                }
            }
        } else {
            // 没有关闭信号处理的原始循环
            loop {
                match self
                    .download_playlist_segments(playlist_url, &mut output_file, m3u_processor)
                    .await
                {
                    Ok((has_new_content, target_duration)) => {
                        // 基于分片目标持续时间更新动态等待时间
                        dynamic_wait_time = if target_duration <= 2 {
                            1 // 对于短分片，每1秒检查一次
                        } else if target_duration <= 6 {
                            target_duration / 2 // 对于中等分片，以一半持续时间检查
                        } else {
                            3 // 对于长分片，每3秒检查一次
                        };

                        if has_new_content {
                            has_downloaded_content = true; // 标记已下载内容
                            consecutive_empty_playlists = 0;
                        } else {
                            consecutive_empty_playlists += 1;
                            debug!(
                                "[{}] 播放列表中没有新分片 ({}/{})",
                                self.username, consecutive_empty_playlists, MAX_EMPTY_PLAYLISTS
                            );
                            if consecutive_empty_playlists >= MAX_EMPTY_PLAYLISTS {
                                info!(
                                    "[{}] 连续 {} 次未发现新分片，直播可能已结束",
                                    self.username, MAX_EMPTY_PLAYLISTS
                                );
                                break Ok(());
                            }
                            // 基于分片目标持续时间等待
                            debug!(
                                "[{}] 等待 {} 秒后重新检查播放列表",
                                self.username, dynamic_wait_time
                            );
                            if self
                                .interruptible_sleep(tokio::time::Duration::from_secs(
                                    dynamic_wait_time,
                                ))
                                .await
                            {
                                break Ok(());
                            }
                        }
                    }
                    Err(e) => {
                        error!("[{}] 下载分片时出错: {}", self.username, e);
                        // 出错时不要立即放弃，等待并重试
                        if self
                            .interruptible_sleep(tokio::time::Duration::from_secs(3))
                            .await
                        {
                            break Err(e);
                        }
                        consecutive_empty_playlists += 1;
                        if consecutive_empty_playlists >= MAX_EMPTY_PLAYLISTS {
                            break Err(e);
                        }
                    }
                }
            }
        };

        drop(output_file);

        // 只有在实际下载了内容时才进行转换
        if has_downloaded_content {
            debug!("[{}] 正在将录制内容转换为 MP4 格式...", self.username);
            match self.convert_ts_to_mp4(&temp_path, output_path).await {
                Ok(()) => {
                    info!("[{}] 视频转换成功完成", self.username);
                }
                Err(e) => {
                    error!("[{}] 视频转换失败: {}", self.username, e);
                    // 即使转换失败，我们仍然要清理并返回原始错误
                }
            }
        } else {
            debug!("[{}] 没有下载任何内容，跳过视频转换", self.username);
        }

        // 清理临时文件
        if temp_path.exists() {
            if let Err(e) = tokio::fs::remove_file(&temp_path).await {
                error!("[{}] 清理临时文件失败: {}", self.username, e);
            }
        }

        download_result
    }

    /// 下载播放列表分片
    async fn download_playlist_segments<F>(
        &mut self,
        playlist_url: &str,
        output_file: &mut File,
        m3u_processor: Option<&F>,
    ) -> Result<(bool, u64)>
    where
        F: Fn(&str) -> String,
    {
        debug!("[{}] 获取播放列表: {}", self.username, playlist_url);

        let response = self
            .client
            .get(playlist_url)
            .header("Accept", "*/*")
            .header("Accept-Language", "en-US,en;q=0.5")
            .header("DNT", "1")
            .header("Connection", "keep-alive")
            .header("Sec-Fetch-Dest", "empty")
            .header("Sec-Fetch-Mode", "cors")
            .header("Sec-Fetch-Site", "cross-site")
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(anyhow!("获取播放列表失败: {}", response.status()));
        }

        let mut content = response.text().await?;

        // 如果提供了 M3U8 处理器，则应用（用于解密）
        if let Some(processor) = m3u_processor {
            debug!(
                "[{}] 原始 M3U8 内容 (前 500 字符): {}",
                self.username,
                &content.chars().take(500).collect::<String>()
            );
            content = processor(&content);
            debug!(
                "[{}] 处理后的 M3U8 内容 (前 500 字符): {}",
                self.username,
                &content.chars().take(500).collect::<String>()
            );
        }

        let mut has_new_content = false; // 跟踪任何新内容（初始化分片或媒体分片）
        let mut target_duration = 6; // 默认分片目标持续时间，将从播放列表更新

        // 从 M3U8 内容提取分片目标持续时间
        for line in content.lines() {
            if line.starts_with("#EXT-X-TARGETDURATION:") {
                if let Some(duration_str) = line.strip_prefix("#EXT-X-TARGETDURATION:") {
                    if let Ok(duration) = duration_str.parse::<u64>() {
                        target_duration = duration;
                        debug!(
                            "[{}] 检测到分片目标持续时间: {} 秒",
                            self.username, target_duration
                        );
                        break;
                    }
                }
            }
        }

        // 检查 #EXT-X-MAP 初始化分片
        if !self.init_segment_downloaded {
            if let Some(init_url) = self.extract_init_segment(&content, playlist_url)? {
                debug!("[{}] 下载初始化分片: {}", self.username, init_url);
                match self.download_segment(&init_url, output_file).await {
                    Ok(()) => {
                        debug!("[{}] 初始化分片下载成功", self.username);
                        self.init_segment_downloaded = true;
                        has_new_content = true; // 标记已下载初始化分片
                    }
                    Err(e) => {
                        error!("[{}] 初始化分片下载失败: {}", self.username, e);
                        return Err(e);
                    }
                }
            }
        }

        let playlist = m3u8_rs::parse_playlist_res(content.as_bytes())
            .map_err(|e| anyhow!("解析 M3U8 失败: {:?}", e))?;

        match playlist {
            m3u8_rs::Playlist::MediaPlaylist(media_playlist) => {
                debug!(
                    "[{}] 播放列表包含 {} 个分片",
                    self.username,
                    media_playlist.segments.len()
                );
                let base_url = Url::parse(playlist_url)?;

                // 统计我们尚未下载的新分片
                let new_segments: Vec<_> = media_playlist
                    .segments
                    .iter()
                    .filter(|segment| !self.downloaded_segments.contains(&segment.uri))
                    .collect();
                let new_segments_count = new_segments.len();
                let total_segments_in_this_round =
                    self.total_processed_segments + new_segments_count;

                let mut current_new_segment_index = 0;

                for segment in &media_playlist.segments {
                    let segment_uri = &segment.uri;

                    if self.downloaded_segments.contains(segment_uri) {
                        debug!("[{}] 分片已下载，跳过: {}", self.username, segment_uri);
                        continue;
                    }

                    current_new_segment_index += 1;
                    self.total_processed_segments += 1;

                    let segment_url = if segment_uri.starts_with("http") {
                        segment_uri.clone()
                    } else {
                        base_url.join(segment_uri)?.to_string()
                    };

                    debug!(
                        "[{}] 下载新分片 ({}/{}): {}",
                        self.username, current_new_segment_index, new_segments_count, segment_url
                    );

                    // 添加正确索引的信息级进度消息
                    info!(
                        "[{}] 正在处理分片 {}/{}",
                        self.username, self.total_processed_segments, total_segments_in_this_round
                    );

                    // 尝试下载分片，但不因单个分片而使整个过程失败
                    match self.download_segment(&segment_url, output_file).await {
                        Ok(()) => {
                            self.downloaded_segments.insert(segment_uri.clone());
                            has_new_content = true; // 标记已下载媒体分片
                        }
                        Err(e) => {
                            // 记录错误但继续处理其他分片
                            // 其中单个分片失败不会停止整个下载过程
                            error!("[{}] 下载分片 {} 失败: {}", self.username, segment_url, e);
                            // 仍标记为"已处理"以避免对坏分片无限重试
                            self.downloaded_segments.insert(segment_uri.clone());
                        }
                    }
                }

                if new_segments_count > 0 {
                    debug!("[{}] 处理了 {} 个新分片", self.username, new_segments_count);
                } else {
                    debug!("[{}] 播放列表中没有新分片", self.username);
                }
            }
            m3u8_rs::Playlist::MasterPlaylist(_) => {
                return Err(anyhow!("此上下文不支持主播放列表"));
            }
        }

        Ok((has_new_content, target_duration))
    }

    /// 下载单个分片
    async fn download_segment(&self, segment_url: &str, output_file: &mut File) -> Result<()> {
        const MAX_RETRIES: u32 = 3;
        let mut retries = 0;

        loop {
            match self.try_download_segment(segment_url, output_file).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    retries += 1;
                    if retries >= MAX_RETRIES {
                        return Err(e);
                    }

                    debug!(
                        "[{}] 分片下载失败 (尝试 {}/{}): {}，正在重试...",
                        self.username, retries, MAX_RETRIES, e
                    );
                    tokio::time::sleep(tokio::time::Duration::from_millis(1000 * retries as u64))
                        .await;
                }
            }
        }
    }

    /// 尝试下载分片（带重试机制）
    async fn try_download_segment(&self, segment_url: &str, output_file: &mut File) -> Result<()> {
        let response = self
            .client
            .get(segment_url)
            .header("Accept", "*/*")
            .header("Accept-Language", "en-US,en;q=0.5")
            .header("DNT", "1")
            .header("Connection", "keep-alive")
            .header("Sec-Fetch-Dest", "empty")
            .header("Sec-Fetch-Mode", "cors")
            .header("Sec-Fetch-Site", "cross-site")
            .send()
            .await?;

        // 处理特定的 HTTP 状态码
        match response.status() {
            reqwest::StatusCode::OK => {
                // 成功，继续下载
            }
            reqwest::StatusCode::IM_A_TEAPOT => {
                // "I'm a teapot" - CDN 经常使用这个状态码表示
                // 分片尚未准备好或暂时不可用
                debug!(
                    "[{}] 分片 {} 返回 418 (teapot)，跳过",
                    self.username, segment_url
                );
                return Ok(()); // 跳过此分片，不作为错误处理
            }
            reqwest::StatusCode::NOT_FOUND => {
                // 分片未找到，可能已过期或尚不可用
                debug!(
                    "[{}] 分片 {} 未找到 (404)，跳过",
                    self.username, segment_url
                );
                return Ok(());
            }
            reqwest::StatusCode::FORBIDDEN => {
                // 禁止访问，可能由于频率限制或访问限制
                debug!(
                    "[{}] 分片 {} 被禁止访问 (403)，跳过",
                    self.username, segment_url
                );
                return Ok(());
            }
            reqwest::StatusCode::TOO_MANY_REQUESTS => {
                // 请求过多 - 应该延迟后重试
                return Err(anyhow!("请求过于频繁 (429)，将重试"));
            }
            status => {
                return Err(anyhow!(
                    "下载分片失败: {} {}",
                    status.as_u16(),
                    status.canonical_reason().unwrap_or("未知")
                ));
            }
        }

        let bytes = response.bytes().await?;
        if bytes.is_empty() {
            debug!("[{}] 分片 {} 为空，跳过", self.username, segment_url);
            return Ok(());
        }

        output_file.write_all(&bytes).await?;
        output_file.flush().await?;
        debug!(
            "[{}] 分片下载成功: {} ({} 字节)",
            self.username,
            segment_url,
            bytes.len()
        );

        Ok(())
    }

    /// 使用 FFmpeg 将 fMP4 转换为 MP4
    async fn convert_ts_to_mp4(&self, input_path: &Path, output_path: &Path) -> Result<()> {
        use std::process::Command;

        debug!("[{}] 使用 FFmpeg 将 fMP4 转换为 MP4...", self.username);

        let output = Command::new("ffmpeg")
            .arg("-i")
            .arg(input_path)
            .arg("-c:a")
            .arg("copy")
            .arg("-c:v")
            .arg("copy")
            .arg("-y") // 覆盖输出文件
            .arg(output_path)
            .output()
            .map_err(|e| {
                anyhow!(
                    "运行 FFmpeg 失败: {}。请确保 FFmpeg 已安装并在 PATH 中。",
                    e
                )
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("FFmpeg 转换失败: {}", stderr));
        }

        info!("[{}] 录制已保存到: {:?}", self.username, output_path);
        Ok(())
    }

    /// 提取初始化分片 URL
    fn extract_init_segment(&self, content: &str, playlist_url: &str) -> Result<Option<String>> {
        // 查找 #EXT-X-MAP:URI="..." 行
        content
            .lines()
            .find(|line| line.starts_with("#EXT-X-MAP:URI="))
            .and_then(|line| {
                line.find("URI=\"")
                    .map(|start| start + 5) // 跳过 "URI=""
                    .and_then(|start| line[start..].find('"').map(|end| &line[start..start + end]))
            })
            .map(|init_uri| {
                // 如需要，将相对 URI 转换为绝对 URI
                let init_url = if init_uri.starts_with("http") {
                    init_uri.to_string()
                } else {
                    let base_url = Url::parse(playlist_url)?;
                    base_url.join(init_uri)?.to_string()
                };

                debug!("[{}] 发现初始化分片: {}", self.username, init_url);
                Ok(init_url)
            })
            .transpose()
    }
}
