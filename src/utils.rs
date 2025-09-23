use anyhow::{Result, anyhow};
use reqwest::{Client, cookie::Jar};
use std::env;
use std::sync::Arc;
use url::Url;

// 重新导出 reqwest 类型以便统一管理
// 这样可以避免在其他模块中直接导入 reqwest，保持统一的客户端管理
pub use reqwest::{StatusCode, Error as ReqwestError};

/// 代理配置结构体
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub url: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl ProxyConfig {
    /// 创建新的代理配置
    pub fn new(url: String, username: Option<String>, password: Option<String>) -> Self {
        Self {
            url,
            username,
            password,
        }
    }

    /// 从配置选项创建代理配置
    pub fn from_options(
        proxy_url: Option<String>,
        proxy_username: Option<String>,
        proxy_password: Option<String>,
    ) -> Option<Self> {
        proxy_url.map(|url| Self::new(url, proxy_username, proxy_password))
    }

    /// 验证代理配置
    pub fn validate(&self) -> Result<()> {
        validate_proxy_url(&self.url)
    }
}

/// 验证代理 URL 格式
pub fn validate_proxy_url(proxy_url: &str) -> Result<()> {
    let url = Url::parse(proxy_url)?;

    match url.scheme() {
        "http" | "https" | "socks5" => Ok(()),
        scheme => Err(anyhow!(
            "不支持的代理协议: {}。支持的协议: http, https, socks5",
            scheme
        )),
    }
}

/// 从环境变量获取代理设置
pub fn get_proxy_from_env() -> Option<String> {
    ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"]
        .iter()
        .find_map(|var| env::var(var).ok())
}

/// 创建带有代理配置和Cookie的 HTTP 客户端
pub fn create_client(
    proxy_url: Option<&str>,
    proxy_username: Option<&str>,
    proxy_password: Option<&str>,
    user_agent: &str,
    cookies: Option<&str>,
) -> Result<(Client, Arc<Jar>)> {
    let jar = Arc::new(Jar::default());

    // 如果提供了cookies，解析并添加到cookie jar中
    if let Some(cookies_str) = cookies {
        let stripchat_url = "https://stripchat.com".parse::<Url>().unwrap();

        // 解析cookie字符串格式：key1=value1; key2=value2
        for cookie_pair in cookies_str.split(';') {
            let cookie_pair = cookie_pair.trim();
            if !cookie_pair.is_empty() {
                let header_value = format!("{}; Domain=stripchat.com; Path=/", cookie_pair);
                jar.add_cookie_str(&header_value, &stripchat_url);
            }
        }
    }

    let mut client_builder = Client::builder()
        .cookie_provider(jar.clone())
        .user_agent(user_agent)
        .timeout(std::time::Duration::from_secs(30))  // 30秒超时
        .connect_timeout(std::time::Duration::from_secs(10))  // 10秒连接超时
        .tcp_keepalive(std::time::Duration::from_secs(30))  // TCP keepalive
        .pool_idle_timeout(std::time::Duration::from_secs(90))  // 连接池空闲超时
        .pool_max_idle_per_host(4)  // 每个主机最大空闲连接数
        .http2_prior_knowledge();  // 优先使用HTTP/2

    // 如果提供了代理，则配置代理
    if let Some(proxy_url) = proxy_url {
        let proxy = reqwest::Proxy::all(proxy_url)?;

        // 如果提供了代理认证，则添加
        let proxy = if let (Some(username), Some(password)) = (proxy_username, proxy_password) {
            proxy.basic_auth(username, password)
        } else {
            proxy
        };

        client_builder = client_builder.proxy(proxy);
    }

    Ok((client_builder.build()?, jar))
}
