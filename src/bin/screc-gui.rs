// Release 构建默认作为 Windows GUI 程序（不弹出控制台窗口）
#![cfg_attr(all(feature = "gui", not(debug_assertions)), windows_subsystem = "windows")]

#[cfg(feature = "gui")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use screc::config::AppConfig;

    let config_path = AppConfig::get_default_config_path();
    let app_config = screc::load_config(&config_path);

    screc::run_gui_mode(app_config, config_path).await
}

#[cfg(not(feature = "gui"))]
fn main() {
    eprintln!("screc-gui 需要启用 gui 特性编译，请使用: cargo build --features gui");
    std::process::exit(1);
}
