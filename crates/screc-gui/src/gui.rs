use std::rc::Rc;

use chrono::Local;
use gpui::*;
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::input::{Input, InputState};
use gpui_component::scroll::ScrollableElement as _;
use gpui_component::switch::Switch;
use gpui_component::tab::{Tab, TabBar};
use gpui_component::table::{TableBody, TableCell, TableHead, TableHeader, TableRow};
use gpui_component::tag::Tag;
use gpui_component::tooltip::Tooltip;
use gpui_component::*;

use crate::shared_state::{LogLevel, ModelStreamStatus, SharedGuiState};

/// GUI 主视图
pub struct AppView {
    gui_state: SharedGuiState,
    selected_tab: usize,
    auto_scroll_logs: bool,
    log_scroll_handle: VirtualListScrollHandle,
    table_scroll_handle: ScrollHandle,
    log_font: SharedString,
    new_model_input: Entity<InputState>,
    new_model_enabled: bool,
    _refresh_task: Task<()>,
    _appearance_subscription: Subscription,
}

impl AppView {
    pub fn new(gui_state: SharedGuiState, window: &mut Window, cx: &mut Context<Self>) -> Self {
        // 检测可用的等宽字体
        let preferred = ["Cascadia Mono", "Consolas", "Courier New"];
        let available = cx.text_system().all_font_names();
        let log_font = preferred
            .iter()
            .find(|f| available.iter().any(|a| a == *f))
            .unwrap_or(&"Microsoft YaHei UI")
            .to_string()
            .into();

        let new_model_input = cx.new(|cx| InputState::new(window, cx).placeholder("输入用户名..."));

        // 同步系统主题并监听变化
        Theme::sync_system_appearance(Some(window), &mut *cx);
        let appearance_subscription = cx.observe_window_appearance(window, |_this, window, cx| {
            Theme::sync_system_appearance(Some(window), &mut *cx);
            cx.notify();
        });

        // 每秒刷新一次，只 spawn 一次
        let refresh_task = cx.spawn(async |entity: WeakEntity<Self>, cx: &mut AsyncApp| {
            loop {
                cx.background_executor()
                    .timer(std::time::Duration::from_secs(1))
                    .await;
                if entity
                    .update(cx, |_this, cx| {
                        cx.notify();
                    })
                    .is_err()
                {
                    break;
                }
            }
        });

        Self {
            gui_state,
            selected_tab: 0,
            auto_scroll_logs: true,
            log_scroll_handle: VirtualListScrollHandle::new(),
            table_scroll_handle: ScrollHandle::new(),
            log_font,
            new_model_input,
            new_model_enabled: true,
            _refresh_task: refresh_task,
            _appearance_subscription: appearance_subscription,
        }
    }

    /// 状态对应的标签颜色
    fn status_tag(status: &ModelStreamStatus, _cx: &App) -> Tag {
        let label = status.label().to_string();
        match status {
            ModelStreamStatus::Public => Tag::success().child(label),
            ModelStreamStatus::Private => Tag::warning().child(label),
            ModelStreamStatus::Offline => Tag::secondary().child(label),
            ModelStreamStatus::LongOffline => Tag::secondary().child(label),
            ModelStreamStatus::Error => Tag::danger().child(label),
            ModelStreamStatus::Unknown => Tag::secondary().child(label),
            ModelStreamStatus::NotExist => Tag::danger().child(label),
            ModelStreamStatus::Restricted => Tag::warning().child(label),
        }
    }

    /// 格式化录制时长
    fn format_duration(start: &chrono::DateTime<Local>) -> String {
        let dur = Local::now().signed_duration_since(start);
        let hours = dur.num_hours();
        let mins = dur.num_minutes() % 60;
        let secs = dur.num_seconds() % 60;
        format!("{:02}:{:02}:{:02}", hours, mins, secs)
    }

    /// 渲染模特状态列表
    fn render_model_list(
        &mut self,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let models = self.gui_state.get_models();

        // 逐行构建表格数据
        let mut rows: Vec<TableRow> = Vec::new();
        for (row_ix, model) in models.iter().enumerate() {
            let enabled = model.enabled;
            let username = model.username.clone();
            let is_recording = model.is_recording;
            let duration_text = if let Some(ref start) = model.recording_start {
                AppView::format_duration(start)
            } else {
                "-".to_string()
            };
            let file_path_text = model.file_path.as_deref().unwrap_or("-").to_string();
            let file_path_full = file_path_text.clone();
            let status_tag = AppView::status_tag(&model.status, cx);
            let (rec_text, rec_color) = if is_recording {
                ("● 录制中", cx.theme().success)
            } else {
                ("○ 待机", cx.theme().muted_foreground)
            };
            let fg_color = cx.theme().foreground;
            let muted_color = cx.theme().muted_foreground;

            let gui_state_toggle = self.gui_state.clone();
            let username_toggle = username.clone();
            let on_toggle = cx.listener(move |_this, checked: &bool, _window, cx| {
                gui_state_toggle.set_model_enabled(&username_toggle, *checked);
                cx.notify();
            });

            let gui_state_delete = self.gui_state.clone();
            let username_delete = username.clone();
            let on_delete = cx.listener(move |_this, _ev, _window, cx| {
                gui_state_delete.remove_model(&username_delete);
                cx.notify();
            });

            let row = TableRow::new()
                .child(
                    TableCell::new().w(px(50.)).child(
                        Switch::new(ElementId::NamedInteger(
                            "model-enabled".into(),
                            row_ix as u64,
                        ))
                        .checked(enabled)
                        .xsmall()
                        .on_click(on_toggle),
                    ),
                )
                .child(
                    TableCell::new().w(px(120.)).child(
                        div()
                            .text_sm()
                            .font_weight(FontWeight::MEDIUM)
                            .child(username.clone()),
                    ),
                )
                .child(TableCell::new().w(px(80.)).child(status_tag))
                .child(
                    TableCell::new()
                        .w(px(80.))
                        .child(div().text_sm().text_color(rec_color).child(rec_text)),
                )
                .child(
                    TableCell::new()
                        .w(px(90.))
                        .child(div().text_sm().text_color(fg_color).child(duration_text)),
                )
                .child(
                    TableCell::new().flex_1().child(
                        div()
                            .id(ElementId::NamedInteger("filepath".into(), row_ix as u64))
                            .text_xs()
                            .text_color(muted_color)
                            .overflow_hidden()
                            .whitespace_nowrap()
                            .text_ellipsis()
                            .tooltip(move |window, cx| {
                                Tooltip::new(file_path_full.clone()).build(window, cx)
                            })
                            .child(file_path_text),
                    ),
                )
                .child(
                    TableCell::new().w(px(60.)).child(
                        Button::new(ElementId::NamedInteger(
                            "delete-model".into(),
                            row_ix as u64,
                        ))
                        .xsmall()
                        .compact()
                        .danger()
                        .label("删除")
                        .on_click(on_delete),
                    ),
                );

            rows.push(row);
        }

        div()
            .flex_1()
            .min_h_0()
            .w_full()
            .v_flex()
            .gap_2()
            // 新增模特工具栏
            .child(
                div()
                    .h_flex()
                    .gap_2()
                    .items_center()
                    .child(div().w(px(200.)).child(Input::new(&self.new_model_input)))
                    .child(
                        div()
                            .h_flex()
                            .gap_1()
                            .items_center()
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(cx.theme().muted_foreground)
                                    .child("启用"),
                            )
                            .child(
                                Switch::new("new-model-enabled")
                                    .checked(self.new_model_enabled)
                                    .xsmall()
                                    .on_click(cx.listener(|this, checked: &bool, _window, cx| {
                                        this.new_model_enabled = *checked;
                                        cx.notify();
                                    })),
                            ),
                    )
                    .child({
                        let input_state = self.new_model_input.clone();
                        let gui_state = self.gui_state.clone();
                        let enabled = self.new_model_enabled;
                        Button::new("add-model")
                            .compact()
                            .primary()
                            .label("添加")
                            .on_click(cx.listener(move |_this, _ev, window, cx| {
                                let username = input_state.read(cx).value().to_string();
                                let username = username.trim().to_string();
                                if !username.is_empty() {
                                    gui_state.add_model(&username, enabled);
                                    input_state.update(cx, |state, cx| {
                                        state.set_value("", window, cx);
                                    });
                                    cx.notify();
                                }
                            }))
                    }),
            )
            // 模特表格（固定表头 + 可滚动表体）
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .v_flex()
                    .w_full()
                    .overflow_hidden()
                    .rounded(cx.theme().radius)
                    .bg(cx.theme().table)
                    // 固定表头
                    .child(
                        TableHeader::new().child(
                            TableRow::new()
                                .child(TableHead::new().w(px(50.)).child("启用"))
                                .child(TableHead::new().w(px(120.)).child("用户名"))
                                .child(TableHead::new().w(px(80.)).child("状态"))
                                .child(TableHead::new().w(px(80.)).child("录制"))
                                .child(TableHead::new().w(px(90.)).child("录制时长"))
                                .child(TableHead::new().flex_1().child("文件路径"))
                                .child(TableHead::new().w(px(60.)).child("操作")),
                        ),
                    )
                    // 可滚动表体
                    .child(
                        div()
                            .relative()
                            .flex_1()
                            .min_h_0()
                            .w_full()
                            .child(
                                div()
                                    .id("model-table-body")
                                    .size_full()
                                    .overflow_y_scroll()
                                    .track_scroll(&self.table_scroll_handle)
                                    .child(TableBody::new().children(rows)),
                            )
                            .vertical_scrollbar(&self.table_scroll_handle),
                    ),
            )
    }

    /// 渲染日志面板
    fn render_log_panel(&self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let logs = self.gui_state.get_logs();
        let log_count = logs.len();

        // 自动滚动到底部
        if self.auto_scroll_logs && log_count > 0 {
            self.log_scroll_handle
                .scroll_to_item(log_count - 1, ScrollStrategy::Top);
        }

        // 每行固定高度（虚拟列表要求），与渲染时 .h(row_height) 保持一致
        let row_height = px(20.);
        let item_sizes = Rc::new(
            (0..log_count)
                .map(|_| size(px(0.), row_height))
                .collect::<Vec<_>>(),
        );

        // 将快照放入 Rc，避免在闭包中多次克隆整个 Vec
        let logs_rc = Rc::new(logs);
        let logs_for_closure = logs_rc.clone();
        let log_font_clone = self.log_font.clone();

        div()
            .flex_1()
            .min_h_0()
            .w_full()
            .v_flex()
            .gap_2()
            // 日志工具栏
            .child(
                div()
                    .h_flex()
                    .justify_between()
                    .items_center()
                    .child(
                        div()
                            .text_xs()
                            .text_color(cx.theme().muted_foreground)
                            .child(format!("共 {} 条日志", log_count)),
                    )
                    .child(
                        div()
                            .h_flex()
                            .gap_1()
                            .items_center()
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(cx.theme().muted_foreground)
                                    .child("自动滚动"),
                            )
                            .child(
                                Switch::new("auto-scroll")
                                    .checked(self.auto_scroll_logs)
                                    .xsmall()
                                    .on_click(cx.listener(|this, checked, _window, cx| {
                                        this.auto_scroll_logs = *checked;
                                        cx.notify();
                                    })),
                            ),
                    ),
            )
            // 日志内容（虚拟滚动）
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .w_full()
                    .bg(cx.theme().background)
                    .border_1()
                    .border_color(cx.theme().border)
                    .rounded(cx.theme().radius)
                    .relative()
                    .child(
                        v_virtual_list(
                            cx.entity().clone(),
                            "log-list",
                            item_sizes,
                            move |_this: &mut AppView, range, _, cx| {
                                range
                                    .map(|ix| {
                                        let entry = &logs_for_closure[ix];
                                        let level_color = match entry.level {
                                            LogLevel::Info => cx.theme().success,
                                            LogLevel::Warn => cx.theme().warning,
                                            LogLevel::Error => cx.theme().danger,
                                            LogLevel::Debug => cx.theme().info,
                                        };
                                        let level_label = entry.level.label().to_string();
                                        let time_str =
                                            entry.timestamp.format("%H:%M:%S%.3f").to_string();

                                        div()
                                            .h(row_height)
                                            .h_flex()
                                            .items_center()
                                            .gap_2()
                                            .text_xs()
                                            .font_family(log_font_clone.clone())
                                            .child(
                                                div()
                                                    .text_color(cx.theme().muted_foreground)
                                                    .flex_shrink_0()
                                                    .child(time_str),
                                            )
                                            .child(
                                                div()
                                                    .text_color(level_color)
                                                    .flex_shrink_0()
                                                    .font_weight(FontWeight::BOLD)
                                                    .child(level_label),
                                            )
                                            .child(
                                                div()
                                                    .text_color(cx.theme().foreground)
                                                    .child(entry.message.clone()),
                                            )
                                    })
                                    .collect()
                            },
                        )
                        .track_scroll(&self.log_scroll_handle)
                        .size_full()
                        .p_2(),
                    )
                    .vertical_scrollbar(&self.log_scroll_handle),
            )
    }
}

impl Render for AppView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let models = self.gui_state.get_models();
        let online_count = models
            .iter()
            .filter(|m| m.status == ModelStreamStatus::Public)
            .count();
        let recording_count = models.iter().filter(|m| m.is_recording).count();
        let total_count = models.len();

        div()
            .v_flex()
            .size_full()
            .bg(cx.theme().background)
            .text_color(cx.theme().foreground)
            // 顶部标题栏
            .child(
                div()
                    .h_flex()
                    .w_full()
                    .px_4()
                    .py_3()
                    .border_b_1()
                    .border_color(cx.theme().border)
                    .bg(cx.theme().title_bar)
                    .items_center()
                    .justify_between()
                    .child(
                        div().h_flex().gap_3().items_center().child(
                            div()
                                .text_base()
                                .font_weight(FontWeight::BOLD)
                                .child("Screc 录制监控"),
                        ),
                    )
                    .child(
                        div()
                            .h_flex()
                            .gap_4()
                            .items_center()
                            .child(
                                div()
                                    .h_flex()
                                    .gap_1()
                                    .items_center()
                                    .child(div().size(px(8.)).rounded_full().bg(cx.theme().success))
                                    .child(div().text_sm().child(format!("在线 {}", online_count))),
                            )
                            .child(
                                div()
                                    .h_flex()
                                    .gap_1()
                                    .items_center()
                                    .child(div().size(px(8.)).rounded_full().bg(cx.theme().danger))
                                    .child(
                                        div().text_sm().child(format!("录制 {}", recording_count)),
                                    ),
                            )
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(cx.theme().muted_foreground)
                                    .child(format!("总计 {}", total_count)),
                            ),
                    ),
            )
            // Tab 栏
            .child(
                div().w_full().px_4().pt_2().child(
                    TabBar::new("main-tabs")
                        .selected_index(self.selected_tab)
                        .on_click(cx.listener(|this, ix, _window, cx| {
                            this.selected_tab = *ix;
                            cx.notify();
                        }))
                        .child(Tab::new().label("模特状态"))
                        .child(Tab::new().label("日志")),
                ),
            )
            // 内容区域
            .child(div().v_flex().flex_1().min_h_0().w_full().p_4().child(
                if self.selected_tab == 0 {
                    self.render_model_list(window, cx).into_any_element()
                } else {
                    self.render_log_panel(window, cx).into_any_element()
                },
            ))
            // 底部状态栏
            .child(
                div()
                    .h_flex()
                    .w_full()
                    .px_4()
                    .py_1()
                    .border_t_1()
                    .border_color(cx.theme().border)
                    .bg(cx.theme().title_bar)
                    .justify_between()
                    .child(
                        div()
                            .text_xs()
                            .text_color(cx.theme().muted_foreground)
                            .child(format!("{}", Local::now().format("%Y-%m-%d %H:%M:%S"))),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(cx.theme().muted_foreground)
                            .child("Screc v0.1.0"),
                    ),
            )
    }
}

/// 启动 GUI 窗口（阻塞调用，在主线程运行）
pub fn run_gui(gui_state: SharedGuiState) {
    let app = gpui_platform::application().with_assets(gpui_component_assets::Assets);

    app.run(move |cx: &mut App| {
        gpui_component::init(cx);

        let gui_state_clone = gui_state.clone();
        cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(Bounds::centered(
                    None,
                    size(px(1000.), px(700.)),
                    cx,
                ))),
                titlebar: Some(TitlebarOptions {
                    title: Some(SharedString::from("Screc 录制监控")),
                    ..Default::default()
                }),
                ..Default::default()
            },
            |window, cx| {
                let view = cx.new(|cx| AppView::new(gui_state_clone, window, cx));
                cx.new(|cx| Root::new(view, window, cx))
            },
        )
        .expect("无法打开窗口");
    });
}
