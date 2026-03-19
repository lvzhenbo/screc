// Release 构建默认作为 Windows GUI 程序（不弹出控制台窗口）
#![cfg_attr(all(feature = "gui", not(debug_assertions)), windows_subsystem = "windows")]

#[cfg(feature = "gui")]
use anyhow::Result;
#[cfg(feature = "gui")]
use screc::config::AppConfig;

#[cfg(feature = "gui")]
#[tokio::main]
async fn main() -> Result<()> {
    let config_path = AppConfig::get_default_config_path();
    let app_config = screc::load_config(&config_path);

    screc::run_gui_mode(app_config, config_path).await
}

#[cfg(not(feature = "gui"))]
fn main() {
    eprintln!("GUI support is not compiled. Build with: cargo build --features gui");
    std::process::exit(1);
}
