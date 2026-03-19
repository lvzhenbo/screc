// Release 构建默认作为 Windows GUI 程序（不弹出控制台窗口）
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use anyhow::Result;
use screc::config::AppConfig;

#[tokio::main]
async fn main() -> Result<()> {
    let config_path = AppConfig::get_default_config_path();
    let app_config = screc::load_config(&config_path);

    screc::run_gui_mode(app_config, config_path).await
}
