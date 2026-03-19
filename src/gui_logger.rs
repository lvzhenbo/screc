use crate::shared_state::{LogLevel, SharedGuiState};
use log::Log;

/// 桥接 `log` crate 到 GUI 共享状态
pub struct GuiLogger {
    gui_state: SharedGuiState,
}

impl GuiLogger {
    pub fn new(gui_state: SharedGuiState) -> Self {
        Self { gui_state }
    }
}

impl Log for GuiLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Debug
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let level = match record.level() {
                log::Level::Error => LogLevel::Error,
                log::Level::Warn => LogLevel::Warn,
                log::Level::Info => LogLevel::Info,
                log::Level::Debug | log::Level::Trace => LogLevel::Debug,
            };
            self.gui_state.push_log(level, format!("{}", record.args()));
        }
    }

    fn flush(&self) {}
}
