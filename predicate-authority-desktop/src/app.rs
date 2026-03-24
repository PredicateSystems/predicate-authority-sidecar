//! Main egui application: desktop companion (launcher + policy + diagnostics).

use crate::api;
use crate::diagnostics;
use crate::keychain;
use crate::launch_args;
use crate::policy_diff;
use crate::policy_ui::{self, PolicyFormat, RuleDraft, TEMPLATE_LABELS};
use crate::presets::{self, LaunchPreset};
use crate::process::ProcessSupervisor;
use crate::sidecar_probe;
use crate::theme;
use egui::{Color32, Frame, Margin, RichText, Rounding, ScrollArea, Stroke};
use regex::Regex;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum MainTab {
    Home,
    Config,
    Policy,
    Logs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PolicyEditMode {
    Builder,
    Raw,
}

pub struct DesktopApp {
    main_tab: MainTab,

    binary_path: String,
    config_path: String,
    policy_path: String,
    host: String,
    port: String,
    web_ui: bool,
    audit_mode: bool,
    reload_secret: String,

    supervisor: ProcessSupervisor,
    log_buffer: VecDeque<String>,
    status_message: String,

    health_line: String,
    status_line: String,
    poll_stop: Option<Arc<AtomicBool>>,
    health_rx: Option<Receiver<String>>,

    policy_edit_mode: PolicyEditMode,
    template_choice: usize,
    rule_drafts: Vec<RuleDraft>,
    raw_policy: String,
    validation_note: String,
    reload_note: String,

    last_sidecar_start: Option<Instant>,
    /// Timestamp-prefixed health/status lines (most recent at the back).
    status_history: VecDeque<String>,
    last_applied_policy_json: Option<String>,
    diff_open: bool,
    diff_text: String,
    config_check_output: String,
    keychain_note: String,
    /// Set after "Generate example TOML" (success or error).
    config_generate_note: String,

    preset_state: presets::PersistedState,
    /// Index into `preset_state.presets` for Load / Delete actions.
    preset_selection: Option<usize>,
    new_preset_name: String,
    preset_message: String,
    sidecar_version_line: String,

    last_repaint_request: Instant,
}

impl DesktopApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        theme::apply(&cc.egui_ctx);
        let preset_state = presets::load();

        let mut binary_path = String::new();
        let mut config_path = String::new();
        let mut policy_path = String::new();
        let mut host = "127.0.0.1".to_string();
        let mut port = "8787".to_string();
        let mut web_ui = true;
        let mut audit_mode = false;

        if preset_state.apply_startup_preset {
            if let Some(name) = &preset_state.startup_preset_name {
                if let Some(p) = preset_state.presets.iter().find(|p| p.name == *name) {
                    binary_path = p.binary_path.clone();
                    config_path = p.config_path.clone();
                    policy_path = p.policy_path.clone();
                    host = p.host.clone();
                    port = p.port.clone();
                    web_ui = p.web_ui;
                    audit_mode = p.audit_mode;
                }
            }
        }

        Self {
            main_tab: MainTab::Home,
            binary_path,
            config_path,
            policy_path,
            host,
            port,
            web_ui,
            audit_mode,
            reload_secret: String::new(),
            supervisor: ProcessSupervisor::default(),
            log_buffer: VecDeque::new(),
            status_message: String::new(),
            health_line: "—".into(),
            status_line: "—".into(),
            poll_stop: None,
            health_rx: None,
            policy_edit_mode: PolicyEditMode::Builder,
            template_choice: 0,
            rule_drafts: vec![RuleDraft::default()],
            raw_policy: String::from("{\n  \"rules\": []\n}\n"),
            validation_note: String::new(),
            reload_note: String::new(),
            last_sidecar_start: None,
            status_history: VecDeque::new(),
            last_applied_policy_json: None,
            diff_open: false,
            diff_text: String::new(),
            config_check_output: String::new(),
            keychain_note: String::new(),
            config_generate_note: String::new(),
            preset_state,
            preset_selection: None,
            new_preset_name: String::new(),
            preset_message: String::new(),
            sidecar_version_line: String::new(),
            last_repaint_request: Instant::now(),
        }
    }

    fn apply_launch_preset(&mut self, p: &LaunchPreset) {
        self.binary_path = p.binary_path.clone();
        self.config_path = p.config_path.clone();
        self.policy_path = p.policy_path.clone();
        self.host = p.host.clone();
        self.port = p.port.clone();
        self.web_ui = p.web_ui;
        self.audit_mode = p.audit_mode;
    }

    fn snapshot_launch_preset(&self, name: String) -> LaunchPreset {
        LaunchPreset {
            name,
            binary_path: self.binary_path.clone(),
            config_path: self.config_path.clone(),
            policy_path: self.policy_path.clone(),
            host: self.host.clone(),
            port: self.port.clone(),
            web_ui: self.web_ui,
            audit_mode: self.audit_mode,
        }
    }

    fn persist_preset_state(&mut self) {
        self.preset_message = match presets::save(&self.preset_state) {
            Ok(()) => "Presets saved.".into(),
            Err(e) => format!("Could not save presets: {e}"),
        };
    }

    fn build_launch_args(&self) -> Result<Vec<String>, String> {
        launch_args::build_sidecar_args(launch_args::LaunchConfig {
            config_path: &self.config_path,
            policy_path: &self.policy_path,
            host: &self.host,
            port: &self.port,
            web_ui: self.web_ui,
            audit_mode: self.audit_mode,
            reload_secret: &self.reload_secret,
        })
    }

    fn push_status_history_line(&mut self, line: String) {
        const MAX: usize = 50;
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.status_history.push_back(format!("{ts} {line}"));
        while self.status_history.len() > MAX {
            self.status_history.pop_front();
        }
    }

    fn canonical_policy_json(&mut self) -> Result<String, String> {
        let rules = self.current_rules_for_apply()?;
        serde_json::to_string_pretty(&serde_json::json!({ "rules": rules }))
            .map_err(|e| e.to_string())
    }

    fn restart_sidecar(&mut self) {
        if self.binary_path.trim().is_empty() {
            self.status_message = "Set sidecar binary path first.".into();
            return;
        }
        self.stop_sidecar();
        self.start_sidecar();
    }

    fn start_sidecar(&mut self) {
        self.status_message.clear();
        let bin = self.binary_path.trim();
        if bin.is_empty() {
            self.status_message = "Set sidecar binary path first.".into();
            return;
        }
        let args = match self.build_launch_args() {
            Ok(a) => a,
            Err(e) => {
                self.status_message = e;
                return;
            }
        };
        if self.policy_path.trim().is_empty() {
            self.status_message =
                "Policy file path is recommended (or use a config that sets policy).".into();
            // still allow start if config sets policy
        }
        match self.supervisor.start(bin, args) {
            Ok(()) => {
                self.status_message = "Sidecar starting…".into();
                self.last_sidecar_start = Some(Instant::now());
                self.start_health_poll();
            }
            Err(e) => self.status_message = e,
        }
    }

    fn stop_sidecar(&mut self) {
        self.stop_health_poll();
        self.supervisor.stop();
        self.status_message = "Stopped.".into();
        self.health_line = "—".into();
        self.status_line = "—".into();
    }

    fn start_health_poll(&mut self) {
        self.stop_health_poll();
        let running = Arc::new(AtomicBool::new(true));
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        let host = self.host.clone();
        let port = self.port.clone();
        let r = running.clone();
        thread::spawn(move || {
            while r.load(Ordering::SeqCst) {
                let line = match api::fetch_health(&host, &port) {
                    Ok(h) => format!(
                        "GET /health → {}  mode={}  uptime={}s",
                        h.status, h.mode, h.uptime_s
                    ),
                    Err(e) => format!("GET /health → error: {e}"),
                };
                let _ = tx.send(line);
                if let Ok(s) = api::fetch_status(&host, &port) {
                    let _ = tx.send(format!(
                        "GET /status → rules={} allowed={} denied={} events={}",
                        s.rule_count, s.total_allowed, s.total_denied, s.event_count
                    ));
                }
                thread::sleep(Duration::from_secs(1));
            }
        });
        self.poll_stop = Some(running);
        self.health_rx = Some(rx);
    }

    fn stop_health_poll(&mut self) {
        if let Some(flag) = self.poll_stop.take() {
            flag.store(false, Ordering::SeqCst);
        }
        self.health_rx = None;
    }

    fn drain_background(&mut self) {
        self.supervisor.drain_logs(&mut self.log_buffer);
        let health_msgs: Vec<String> = if let Some(rx) = self.health_rx.as_ref() {
            let mut v = Vec::new();
            while let Ok(m) = rx.try_recv() {
                v.push(m);
            }
            v
        } else {
            Vec::new()
        };
        for msg in health_msgs {
            if msg.starts_with("GET /health") {
                if self.health_line != msg {
                    self.push_status_history_line(format!("[health] {msg}"));
                }
                self.health_line = msg;
            } else {
                if self.status_line != msg {
                    self.push_status_history_line(format!("[status] {msg}"));
                }
                self.status_line = msg;
            }
        }
        if let Some(status) = self.supervisor.poll_exit() {
            self.stop_health_poll();
            self.status_message = format!("Sidecar exited: {status}");
        }
        self.maybe_capture_web_ui_url();
    }

    fn maybe_capture_web_ui_url(&mut self) {
        static RE: OnceLock<Regex> = OnceLock::new();
        let re = RE.get_or_init(|| Regex::new(r"Web UI enabled:\s*(http://\S+)").unwrap());
        for line in self.log_buffer.iter().rev().take(400) {
            if let Some(c) = re.captures(line) {
                if let Some(m) = c.get(1) {
                    let url = m.as_str().to_string();
                    if !self.status_message.contains(&url) {
                        self.status_message = format!("Web UI: open {url}");
                    }
                    break;
                }
            }
        }
    }

    fn open_dashboard_url(&self) {
        static RE: OnceLock<Regex> = OnceLock::new();
        let re = RE.get_or_init(|| Regex::new(r"Web UI enabled:\s*(http://\S+)").unwrap());
        for line in self.log_buffer.iter().rev() {
            if let Some(c) = re.captures(line) {
                if let Some(m) = c.get(1) {
                    let url = m.as_str().to_string();
                    let _ = open::that(&url);
                    return;
                }
            }
        }
        // Fallback: no token
        let base = api::base_url(&self.host, &self.port);
        let _ = open::that(format!("{}/ui/", base.trim_end_matches('/')));
    }

    fn apply_template(&mut self) {
        let rules = policy_ui::template_rules(self.template_choice);
        if rules.is_empty() {
            self.rule_drafts.clear();
            self.rule_drafts.push(RuleDraft::default());
        } else {
            self.rule_drafts = rules.iter().map(RuleDraft::from_rule).collect();
        }
        self.sync_builder_to_raw();
        self.validation_note.clear();
    }

    fn sync_builder_to_raw(&mut self) {
        if let Ok(rules) = policy_ui::drafts_to_rules(&self.rule_drafts) {
            if let Ok(s) = serde_json::to_string_pretty(&serde_json::json!({ "rules": rules })) {
                self.raw_policy = s;
            }
        }
    }

    fn sync_raw_to_builder_if_possible(&mut self) {
        let path = PathBuf::from(self.policy_path.trim());
        let fmt = if path.extension().and_then(|e| e.to_str()) == Some("yaml")
            || path.extension().and_then(|e| e.to_str()) == Some("yml")
        {
            PolicyFormat::Yaml
        } else {
            PolicyFormat::Json
        };
        match policy_ui::validate_rules_raw(&self.raw_policy, fmt) {
            Ok(rules) => {
                self.rule_drafts = rules.iter().map(RuleDraft::from_rule).collect();
                if self.rule_drafts.is_empty() {
                    self.rule_drafts.push(RuleDraft::default());
                }
                self.validation_note = "Parsed raw policy into builder.".into();
            }
            Err(e) => self.validation_note = format!("Raw parse failed (builder unchanged): {e}"),
        }
    }

    fn current_rules_for_apply(
        &mut self,
    ) -> Result<Vec<predicate_authorityd::models::PolicyRule>, String> {
        match self.policy_edit_mode {
            PolicyEditMode::Builder => policy_ui::drafts_to_rules(&self.rule_drafts),
            PolicyEditMode::Raw => {
                let path = PathBuf::from(self.policy_path.trim());
                policy_ui::validate_rules_json_or_yaml(&self.raw_policy, &path)
            }
        }
    }
}

impl eframe::App for DesktopApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_background();

        if self.last_repaint_request.elapsed() > Duration::from_millis(200) {
            self.last_repaint_request = Instant::now();
            ctx.request_repaint_after(Duration::from_millis(200));
        }

        let tab_frame = Frame::none()
            .fill(ctx.style().visuals.panel_fill)
            .inner_margin(Margin::symmetric(14.0, 10.0))
            .stroke(Stroke::new(
                1.0,
                ctx.style().visuals.widgets.noninteractive.bg_stroke.color,
            ));
        egui::TopBottomPanel::top("top_tabs")
            .frame(tab_frame)
            .show_separator_line(true)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 6.0;
                    tab_select(ui, &mut self.main_tab, MainTab::Home, "Home");
                    tab_select(ui, &mut self.main_tab, MainTab::Config, "Config");
                    tab_select(ui, &mut self.main_tab, MainTab::Policy, "Policy");
                    tab_select(ui, &mut self.main_tab, MainTab::Logs, "Logs");
                });
            });

        let central = Frame::none()
            .fill(ctx.style().visuals.window_fill)
            .inner_margin(Margin::symmetric(18.0, 16.0));
        egui::CentralPanel::default()
            .frame(central)
            .show(ctx, |ui| {
                // Logs keeps its own inner ScrollArea sized to the viewport; avoid nested outer scroll.
                if self.main_tab == MainTab::Logs {
                    self.ui_logs(ui);
                    return;
                }
                ScrollArea::vertical()
                    .id_salt(("central_tab", self.main_tab))
                    .auto_shrink([false, false])
                    .show(ui, |ui| match self.main_tab {
                        MainTab::Home => self.ui_home(ui),
                        MainTab::Config => self.ui_config(ui),
                        MainTab::Policy => self.ui_policy(ui),
                        MainTab::Logs => {}
                    });
            });
    }
}

impl DesktopApp {
    fn ui_home(&mut self, ui: &mut egui::Ui) {
        ui.heading("Predicate Authority");
        ui.label(
            RichText::new("Local sidecar launcher, policy editing, and diagnostics.")
                .color(theme::MUTED),
        );
        ui.add_space(14.0);

        let running = self.supervisor.is_running();
        section_card(ui, "Sidecar", |ui| {
            ui.horizontal(|ui| {
                let start =
                    egui::Button::new(RichText::new("Start").strong().color(Color32::WHITE))
                        .fill(theme::ACCENT)
                        .rounding(Rounding::same(6.0))
                        .min_size(egui::vec2(100.0, 32.0));
                if ui.add_enabled(!running, start).clicked() {
                    self.start_sidecar();
                }
                if ui
                    .add_enabled(
                        running,
                        egui::Button::new("Stop")
                            .rounding(Rounding::same(6.0))
                            .min_size(egui::vec2(88.0, 32.0)),
                    )
                    .clicked()
                {
                    self.stop_sidecar();
                }
                if ui
                    .add_enabled(
                        running,
                        egui::Button::new("Restart")
                            .rounding(Rounding::same(6.0))
                            .min_size(egui::vec2(88.0, 32.0)),
                    )
                    .clicked()
                {
                    self.restart_sidecar();
                }
            });
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("State:").color(theme::MUTED));
                ui.label(
                    RichText::new(if running { "Running" } else { "Stopped" })
                        .strong()
                        .color(if running { theme::OK } else { theme::MUTED }),
                );
            });
            if !self.status_message.is_empty() {
                ui.add_space(4.0);
                ui.label(RichText::new(&self.status_message).italics());
            }
        });

        ui.add_space(12.0);
        section_card(ui, "Endpoints & policy", |ui| {
            ui.label(
                RichText::new(format!("Listen  {}:{}", self.host.trim(), self.port.trim(),))
                    .monospace(),
            );
            ui.label(
                RichText::new(format!(
                    "Web UI {}  ·  Audit {}",
                    if self.web_ui { "on" } else { "off" },
                    if self.audit_mode { "on" } else { "off" },
                ))
                .color(theme::MUTED),
            );
            let pol = self.policy_path.trim();
            ui.label(if pol.is_empty() {
                RichText::new("Policy file: not set (configure in Config)").color(theme::MUTED)
            } else {
                RichText::new(format!("Policy file: {pol}")).monospace()
            });
            match self.last_sidecar_start {
                Some(t) => ui.label(
                    RichText::new(format!("Last start: {:.0}s ago", t.elapsed().as_secs_f32()))
                        .color(theme::MUTED),
                ),
                None => ui.label(RichText::new("Last start: —").color(theme::MUTED)),
            }
        });

        ui.add_space(12.0);
        section_card(ui, "Live health", |ui| {
            mono_block(ui, &self.health_line);
            mono_block(ui, &self.status_line);
            ui.add_space(6.0);
            ui.collapsing(RichText::new("Recent samples").color(theme::MUTED), |ui| {
                if self.status_history.is_empty() {
                    ui.label(RichText::new("No samples yet.").color(theme::MUTED));
                } else {
                    let h = (ui.available_height() * 0.85).clamp(72.0, 200.0);
                    ScrollArea::vertical().max_height(h).show(ui, |ui| {
                        for line in &self.status_history {
                            ui.label(RichText::new(line).monospace().small());
                        }
                    });
                }
            });
        });

        ui.add_space(12.0);
        ui.horizontal(|ui| {
            let dash = egui::Button::new(RichText::new("Open dashboard in browser").strong())
                .rounding(Rounding::same(6.0))
                .min_size(egui::vec2(0.0, 30.0));
            if ui.add(dash).clicked() {
                self.open_dashboard_url();
            }
            ui.label(
                RichText::new("Uses URL from logs when Web UI is enabled.")
                    .small()
                    .color(theme::MUTED),
            );
        });
    }

    fn ui_config(&mut self, ui: &mut egui::Ui) {
        ui.heading("Configuration");
        ui.label(
            RichText::new("Paths and flags passed before `run`. The app builds the CLI for you.")
                .color(theme::MUTED),
        );
        ui.add_space(10.0);

        section_card(ui, "Paths", |ui| {
            path_row(
                ui,
                "Sidecar binary",
                &mut self.binary_path,
                FilePick::Executable,
            );
            if let Some(p) = sidecar_probe::sibling_sidecar_binary() {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Alongside app").color(theme::MUTED));
                    ui.label(RichText::new(p.display().to_string()).monospace().small());
                    if ui.button("Use as binary").clicked() {
                        self.binary_path = p.display().to_string();
                    }
                });
                if let Some((len, mtime)) = sidecar_probe::binary_file_meta(&p) {
                    ui.label(
                        RichText::new(format!("{len} bytes · modified {mtime}"))
                            .small()
                            .color(theme::MUTED),
                    );
                }
                ui.add_space(4.0);
            }
            path_row(ui, "Config TOML", &mut self.config_path, FilePick::Any);
            ui.horizontal_wrapped(|ui| {
                if ui.button("Generate example TOML…").clicked() {
                    if let Some(p) = rfd::FileDialog::new()
                        .set_file_name("predicate-authorityd.toml")
                        .save_file()
                    {
                        let content = predicate_authorityd::config::Config::example_toml();
                        match std::fs::write(&p, &content) {
                            Ok(()) => {
                                self.config_path = p.display().to_string();
                                self.config_generate_note = format!(
                                    "Wrote example TOML to {} (same as `init-config`).",
                                    p.display()
                                );
                            }
                            Err(e) => {
                                self.config_generate_note = format!("Could not write file: {e}");
                            }
                        }
                    }
                }
                ui.label(
                    RichText::new(
                        "Uses the daemon’s built-in example; edit paths and secrets after saving.",
                    )
                    .small()
                    .color(theme::MUTED),
                );
            });
            if !self.config_generate_note.is_empty() {
                let ok = !self.config_generate_note.starts_with("Could not");
                ui.label(RichText::new(&self.config_generate_note).color(if ok {
                    theme::OK
                } else {
                    ui.visuals().error_fg_color
                }));
            }
            path_row(ui, "Policy file", &mut self.policy_path, FilePick::Any);
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui.button("Query sidecar --version").clicked() {
                    self.sidecar_version_line =
                        match sidecar_probe::version_for_binary(&self.binary_path) {
                            Ok(s) => s,
                            Err(e) => e,
                        };
                }
            });
            if !self.sidecar_version_line.is_empty() {
                mono_block(ui, &self.sidecar_version_line);
            }
        });

        ui.add_space(10.0);
        section_card(ui, "Startup presets", |ui| {
            ui.label(
                RichText::new(match presets::state_path() {
                    Some(p) => format!(
                        "Stored at {} (reload secret is not saved here).",
                        p.display()
                    ),
                    None => "Preset file location unavailable on this system.".into(),
                })
                .small()
                .color(theme::MUTED),
            );
            ui.add_space(8.0);
            if ui
                .checkbox(
                    &mut self.preset_state.apply_startup_preset,
                    "Apply a preset automatically when the app starts",
                )
                .changed()
            {
                self.persist_preset_state();
            }
            ui.horizontal(|ui| {
                ui.label("Startup preset:");
                let mut pick = self.preset_state.startup_preset_name.clone();
                egui::ComboBox::from_id_salt("launch_preset_pick")
                    .width((ui.available_width() - 100.0).max(160.0))
                    .selected_text(pick.as_deref().unwrap_or("(none)"))
                    .show_ui(ui, |ui| {
                        if ui.selectable_label(pick.is_none(), "(none)").clicked() {
                            pick = None;
                        }
                        for p in &self.preset_state.presets {
                            let selected = pick.as_ref() == Some(&p.name);
                            if ui.selectable_label(selected, &p.name).clicked() {
                                pick = Some(p.name.clone());
                            }
                        }
                    });
                if pick != self.preset_state.startup_preset_name {
                    self.preset_state.startup_preset_name = pick;
                    self.persist_preset_state();
                }
            });
            ui.add_space(8.0);
            ui.label(
                RichText::new("Manage presets")
                    .strong()
                    .color(ui.visuals().widgets.noninteractive.fg_stroke.color),
            );
            ui.add_space(4.0);
            let mut idx = self.preset_selection;
            egui::ComboBox::from_id_salt("preset_editor_pick")
                .selected_text(
                    idx.and_then(|i| self.preset_state.presets.get(i))
                        .map(|p| p.name.as_str())
                        .unwrap_or("(none)"),
                )
                .show_ui(ui, |ui| {
                    if ui.selectable_label(idx.is_none(), "(none)").clicked() {
                        idx = None;
                    }
                    for (i, p) in self.preset_state.presets.iter().enumerate() {
                        let selected = idx == Some(i);
                        if ui.selectable_label(selected, &p.name).clicked() {
                            idx = Some(i);
                        }
                    }
                });
            self.preset_selection = idx;
            ui.horizontal_wrapped(|ui| {
                if ui.button("Load into form").clicked() {
                    if let Some(i) = self.preset_selection {
                        if let Some(p) = self.preset_state.presets.get(i).cloned() {
                            self.apply_launch_preset(&p);
                            self.preset_message = format!("Loaded preset \"{}\".", p.name);
                        }
                    } else {
                        self.preset_message = "Select a preset first.".into();
                    }
                }
                if ui.button("Delete selected").clicked() {
                    if let Some(i) = self.preset_selection {
                        if i < self.preset_state.presets.len() {
                            let removed = self.preset_state.presets.remove(i);
                            if self.preset_state.startup_preset_name.as_ref() == Some(&removed.name)
                            {
                                self.preset_state.startup_preset_name = None;
                            }
                            self.preset_selection = None;
                            self.persist_preset_state();
                        }
                    }
                }
            });
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label("New name");
                let name_w = (ui.available_width() * 0.4).clamp(140.0, 280.0);
                stateful_singleline(ui, &mut self.new_preset_name, name_w, false);
                if ui.button("Save current as preset").clicked() {
                    let name = self.new_preset_name.trim().to_string();
                    if name.is_empty() {
                        self.preset_message = "Enter a preset name.".into();
                    } else {
                        let snap = self.snapshot_launch_preset(name.clone());
                        if let Some(pos) = self
                            .preset_state
                            .presets
                            .iter()
                            .position(|p| p.name == name)
                        {
                            self.preset_state.presets[pos] = snap;
                        } else {
                            self.preset_state.presets.push(snap);
                        }
                        self.persist_preset_state();
                    }
                }
            });
            if !self.preset_message.is_empty() {
                ui.add_space(6.0);
                let is_err = self.preset_message.starts_with("Could not")
                    || self.preset_message.contains("Enter a")
                    || self.preset_message.contains("Select a");
                ui.label(RichText::new(&self.preset_message).color(if is_err {
                    ui.visuals().error_fg_color
                } else {
                    theme::OK
                }));
            }
        });

        ui.add_space(10.0);
        section_card(ui, "Listen address", |ui| {
            ui.horizontal(|ui| {
                ui.label("Host");
                stateful_singleline(
                    ui,
                    &mut self.host,
                    (ui.available_width() * 0.35).clamp(120.0, 280.0),
                    true,
                );
                ui.label("Port");
                stateful_singleline(
                    ui,
                    &mut self.port,
                    (ui.available_width() * 0.2).clamp(64.0, 120.0),
                    true,
                );
            });
            ui.add_space(6.0);
            ui.checkbox(&mut self.web_ui, "Enable Web UI (--web-ui)");
            ui.checkbox(&mut self.audit_mode, "Audit mode (--audit-mode)");
        });

        ui.add_space(10.0);
        section_card(ui, "Policy reload secret", |ui| {
            ui.label(
                RichText::new("Optional; must match --policy-reload-secret on the daemon.")
                    .small()
                    .color(theme::MUTED),
            );
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.reload_secret)
                        .desired_width((ui.available_width() - 8.0).max(200.0))
                        .password(true),
                );
            });

            ui.add_space(10.0);
            ui.label(
                RichText::new("Keychain")
                    .strong()
                    .color(ui.visuals().widgets.noninteractive.fg_stroke.color),
            );
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                if ui.button("Save to keychain").clicked() {
                    self.keychain_note =
                        match keychain::save_reload_secret(self.reload_secret.trim()) {
                            Ok(()) => "Saved to keychain.".into(),
                            Err(e) => e,
                        };
                }
                if ui.button("Load from keychain").clicked() {
                    self.keychain_note = match keychain::load_reload_secret() {
                        Ok(s) => {
                            self.reload_secret = s;
                            "Loaded from keychain.".into()
                        }
                        Err(e) => e,
                    };
                }
                if ui.button("Clear keychain").clicked() {
                    self.keychain_note = match keychain::delete_reload_secret() {
                        Ok(()) => "Keychain entry removed (if it existed).".into(),
                        Err(e) => e,
                    };
                }
            });
            if !self.keychain_note.is_empty() {
                ui.add_space(4.0);
                ui.label(&self.keychain_note);
            }
        });

        ui.add_space(10.0);
        section_card(ui, "Validate & preview", |ui| {
            if ui
                .add(
                    egui::Button::new(RichText::new("Run check-config").strong())
                        .rounding(Rounding::same(6.0)),
                )
                .clicked()
            {
                self.config_check_output =
                    match launch_args::run_check_config(&self.binary_path, &self.config_path) {
                        Ok(s) => s,
                        Err(e) => e,
                    };
            }
            ui.add_space(6.0);
            ui.collapsing(
                RichText::new("check-config output").color(theme::MUTED),
                |ui| {
                    if self.config_check_output.is_empty() {
                        ui.label(
                            RichText::new("Run check-config to see output.").color(theme::MUTED),
                        );
                    } else {
                        mono_block(ui, &self.config_check_output);
                    }
                },
            );
            ui.add_space(8.0);
            ui.collapsing(
                RichText::new("Launch command preview").color(theme::MUTED),
                |ui| {
                    let preview = match self.build_launch_args() {
                        Ok(args) => {
                            let mut s = self.binary_path.trim().to_string();
                            for a in args {
                                s.push(' ');
                                if a.contains(' ') {
                                    s.push('"');
                                    s.push_str(&a);
                                    s.push('"');
                                } else {
                                    s.push_str(&a);
                                }
                            }
                            s.push_str(" run");
                            s
                        }
                        Err(e) => e,
                    };
                    mono_block(ui, &preview);
                },
            );
        });
    }

    fn ui_policy(&mut self, ui: &mut egui::Ui) {
        ui.heading("Policy");
        ui.label(
            RichText::new("Edit locally, validate, save to disk, then reload the running sidecar.")
                .color(theme::MUTED),
        );
        ui.add_space(8.0);

        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 8.0;
            for (mode, label) in [
                (PolicyEditMode::Builder, "Builder"),
                (PolicyEditMode::Raw, "Raw JSON / YAML"),
            ] {
                let sel = self.policy_edit_mode == mode;
                let b = egui::Button::new(if sel {
                    RichText::new(label).strong()
                } else {
                    RichText::new(label)
                })
                .fill(if sel {
                    theme::ACCENT
                } else {
                    ui.visuals().faint_bg_color
                })
                .stroke(Stroke::new(
                    1.0,
                    if sel {
                        theme::ACCENT
                    } else {
                        ui.visuals().widgets.noninteractive.bg_stroke.color
                    },
                ))
                .rounding(Rounding::same(6.0))
                .min_size(egui::vec2(120.0, 30.0));
                if ui.add(b).clicked() {
                    self.policy_edit_mode = mode;
                }
            }
        });
        ui.add_space(10.0);

        match self.policy_edit_mode {
            PolicyEditMode::Builder => {
                ui.horizontal(|ui| {
                    egui::ComboBox::from_id_salt("tpl")
                        .selected_text(
                            TEMPLATE_LABELS[self
                                .template_choice
                                .min(TEMPLATE_LABELS.len().saturating_sub(1))],
                        )
                        .show_ui(ui, |ui| {
                            for (i, label) in TEMPLATE_LABELS.iter().enumerate() {
                                ui.selectable_value(&mut self.template_choice, i, *label);
                            }
                        });
                    if ui.button("Apply template").clicked() {
                        self.apply_template();
                    }
                    if ui.button("Add rule").clicked() {
                        self.rule_drafts.push(RuleDraft::default());
                        self.sync_builder_to_raw();
                    }
                });

                let scroll_h = (ui.max_rect().height() * 0.38).clamp(160.0, 420.0);
                ScrollArea::vertical().max_height(scroll_h).show(ui, |ui| {
                    let mut remove: Option<usize> = None;
                    let mut duplicate_at: Option<usize> = None;
                    let mut move_up: Option<usize> = None;
                    let mut move_down: Option<usize> = None;
                    let rule_count = self.rule_drafts.len();
                    for (i, d) in self.rule_drafts.iter_mut().enumerate() {
                        Frame::none()
                            .fill(ui.visuals().extreme_bg_color)
                            .inner_margin(Margin::same(10.0))
                            .rounding(Rounding::same(6.0))
                            .stroke(Stroke::new(
                                1.0,
                                ui.visuals().widgets.noninteractive.bg_stroke.color,
                            ))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.label(format!("Rule {}", i + 1));
                                    if ui.small_button("Remove").clicked() {
                                        remove = Some(i);
                                    }
                                    if ui.small_button("Duplicate").clicked() {
                                        duplicate_at = Some(i);
                                    }
                                    if i > 0 && ui.small_button("Up").clicked() {
                                        move_up = Some(i);
                                    }
                                    if i + 1 < rule_count && ui.small_button("Down").clicked() {
                                        move_down = Some(i);
                                    }
                                });
                                ui.horizontal(|ui| {
                                    ui.label("Name");
                                    ui.text_edit_singleline(&mut d.name);
                                });
                                ui.horizontal(|ui| {
                                    ui.checkbox(&mut d.allow, "Allow (else deny)");
                                });
                                ui.label("Principals (comma or newline)");
                                ui.add(
                                    egui::TextEdit::multiline(&mut d.principals).desired_rows(2),
                                );
                                ui.label("Actions");
                                ui.add(egui::TextEdit::multiline(&mut d.actions).desired_rows(2));
                                ui.label("Resources");
                                ui.add(egui::TextEdit::multiline(&mut d.resources).desired_rows(2));
                            });
                    }
                    if let Some(i) = remove {
                        if self.rule_drafts.len() > 1 {
                            self.rule_drafts.remove(i);
                            self.sync_builder_to_raw();
                        }
                    }
                    if let Some(i) = duplicate_at {
                        let copy = self.rule_drafts[i].clone();
                        self.rule_drafts.insert(i + 1, copy);
                        self.sync_builder_to_raw();
                    }
                    if let Some(i) = move_up {
                        if i > 0 {
                            self.rule_drafts.swap(i, i - 1);
                            self.sync_builder_to_raw();
                        }
                    }
                    if let Some(i) = move_down {
                        if i + 1 < self.rule_drafts.len() {
                            self.rule_drafts.swap(i, i + 1);
                            self.sync_builder_to_raw();
                        }
                    }
                });
            }
            PolicyEditMode::Raw => {
                ui.label(
                    RichText::new(
                        "Document shape: rules array. File extension .yaml / .yml selects YAML.",
                    )
                    .color(theme::MUTED)
                    .small(),
                );
                ui.add_space(4.0);
                let rows = ((ui.available_height() / 18.0).floor() as usize).clamp(10, 48);
                ui.add(
                    egui::TextEdit::multiline(&mut self.raw_policy)
                        .desired_width(f32::INFINITY)
                        .desired_rows(rows)
                        .font(egui::TextStyle::Monospace),
                );
                if ui.button("Try parse → builder").clicked() {
                    self.sync_raw_to_builder_if_possible();
                }
            }
        }

        ui.separator();
        ui.horizontal(|ui| {
            if ui.button("Import…").clicked() {
                if let Some(p) = rfd::FileDialog::new().pick_file() {
                    match std::fs::read_to_string(&p) {
                        Ok(s) => {
                            self.raw_policy = s;
                            self.policy_edit_mode = PolicyEditMode::Raw;
                            self.sync_raw_to_builder_if_possible();
                            self.validation_note = format!("Imported {} (raw tab).", p.display());
                        }
                        Err(e) => self.validation_note = format!("Import failed: {e}"),
                    }
                }
            }
            if ui.button("Export…").clicked() {
                if let Some(p) = rfd::FileDialog::new()
                    .set_file_name("policy.json")
                    .save_file()
                {
                    self.validation_note = match self.current_rules_for_apply() {
                        Ok(rules) => match policy_ui::save_rules_json(&p, &rules) {
                            Ok(()) => format!("Exported to {}.", p.display()),
                            Err(e) => format!("Export failed: {e}"),
                        },
                        Err(e) => format!("Cannot export: {e}"),
                    };
                }
            }
            if ui.button("Diff vs last applied").clicked() {
                let old = self.last_applied_policy_json.clone().unwrap_or_default();
                self.diff_text = match self.canonical_policy_json() {
                    Ok(cur) => policy_diff::unified_line_diff(&old, &cur),
                    Err(e) => e,
                };
                self.diff_open = true;
            }
        });

        ui.separator();
        ui.horizontal(|ui| {
            if ui.button("Validate").clicked() {
                self.validation_note = match self.current_rules_for_apply() {
                    Ok(rules) => format!("OK — {} rules", rules.len()),
                    Err(e) => format!("Invalid: {e}"),
                };
            }
            if ui.button("Save to policy file").clicked() {
                let p = self.policy_path.trim().to_string();
                if p.is_empty() {
                    self.validation_note = "Set policy file path in Config.".into();
                } else {
                    self.validation_note = match self.current_rules_for_apply() {
                        Ok(rules) => {
                            match policy_ui::save_rules_json(std::path::Path::new(&p), &rules) {
                                Ok(()) => format!("Saved {p}"),
                                Err(e) => format!("Save failed: {e}"),
                            }
                        }
                        Err(e) => format!("Not saved: {e}"),
                    };
                }
            }
            if ui.button("Reload running sidecar").clicked() {
                let host = self.host.clone();
                let port = self.port.clone();
                let secret_owned = self.reload_secret.trim().to_string();
                let secret = if secret_owned.is_empty() {
                    None
                } else {
                    Some(secret_owned.as_str())
                };
                self.reload_note = match self.current_rules_for_apply() {
                    Ok(rules) => {
                        let rules_for_snapshot = rules.clone();
                        match api::policy_reload(&host, &port, &rules, secret) {
                            Ok(r) => {
                                if let Ok(pretty) = serde_json::to_string_pretty(
                                    &serde_json::json!({ "rules": rules_for_snapshot }),
                                ) {
                                    self.last_applied_policy_json = Some(pretty);
                                }
                                format!("Reload OK: {} — {}", r.rule_count, r.message)
                            }
                            Err(e) => e,
                        }
                    }
                    Err(e) => format!("Reload skipped: {e}"),
                };
            }
        });
        if !self.validation_note.is_empty() {
            ui.label(&self.validation_note);
        }
        if !self.reload_note.is_empty() {
            ui.label(
                RichText::new(&self.reload_note)
                    .color(theme::ACCENT)
                    .strong(),
            );
        }

        egui::Window::new(RichText::new("Diff vs last applied").strong())
            .open(&mut self.diff_open)
            .default_size([580.0, 440.0])
            .frame(
                Frame::window(ui.style())
                    .rounding(Rounding::same(10.0))
                    .stroke(Stroke::new(1.0, ui.visuals().window_stroke.color)),
            )
            .show(ui.ctx(), |ui| {
                let h = ui.available_height().max(120.0);
                ScrollArea::vertical().max_height(h).show(ui, |ui| {
                    ui.label(RichText::new(&self.diff_text).monospace().small());
                });
            });
    }

    fn ui_logs(&mut self, ui: &mut egui::Ui) {
        ui.heading("Process output");
        ui.label(
            RichText::new("Stdout and stderr from the managed sidecar process.")
                .color(theme::MUTED),
        );
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if ui
                .add(
                    egui::Button::new(RichText::new("Export diagnostics ZIP").strong())
                        .rounding(Rounding::same(6.0)),
                )
                .clicked()
            {
                if let Some(path) = rfd::FileDialog::new()
                    .set_file_name("predicate-desktop-diagnostics.zip")
                    .save_file()
                {
                    match std::fs::File::create(&path) {
                        Ok(f) => {
                            let logs = self.log_buffer.iter().cloned().collect::<Vec<_>>().join("\n");
                            let meta = format!(
                                "binary_path={}\nconfig_path={}\npolicy_path={}\nhost={}\nport={}\nweb_ui={}\naudit_mode={}\n",
                                self.binary_path.trim(),
                                self.config_path.trim(),
                                self.policy_path.trim(),
                                self.host.trim(),
                                self.port.trim(),
                                self.web_ui,
                                self.audit_mode
                            );
                            match diagnostics::write_diagnostics_zip(f, &logs, &meta) {
                                Ok(()) => {
                                    self.status_message =
                                        format!("Diagnostics: {}", path.display());
                                }
                                Err(e) => {
                                    self.status_message =
                                        format!("Diagnostics export failed: {e}");
                                }
                            }
                        }
                        Err(e) => {
                            self.status_message = format!("Could not create zip: {e}");
                        }
                    }
                }
            }
            ui.label(
                RichText::new("README, logs, path summary.")
                    .small()
                    .color(theme::MUTED),
            );
        });
        ui.add_space(6.0);
        let log_h = ui.available_height().max(80.0);
        ScrollArea::vertical()
            .max_height(log_h)
            .auto_shrink([false, false])
            .stick_to_bottom(true)
            .show(ui, |ui| {
                Frame::none()
                    .fill(ui.visuals().extreme_bg_color)
                    .inner_margin(Margin::symmetric(8.0, 6.0))
                    .rounding(Rounding::same(6.0))
                    .show(ui, |ui| {
                        for line in &self.log_buffer {
                            ui.label(RichText::new(line).monospace().small());
                        }
                    });
            });
    }
}

#[derive(Clone, Copy)]
enum FilePick {
    Any,
    Executable,
}

fn tab_select(ui: &mut egui::Ui, current: &mut MainTab, value: MainTab, label: &str) {
    let selected = *current == value;
    let w = egui::Button::new(if selected {
        RichText::new(label).strong().color(Color32::WHITE)
    } else {
        RichText::new(label)
    })
    .fill(if selected {
        theme::ACCENT
    } else {
        ui.visuals().faint_bg_color
    })
    .stroke(Stroke::new(
        1.0,
        if selected {
            theme::ACCENT
        } else {
            ui.visuals().widgets.noninteractive.bg_stroke.color
        },
    ))
    .rounding(Rounding::same(6.0))
    .min_size(egui::vec2(78.0, 30.0));
    if ui.add(w).clicked() {
        *current = value;
    }
}

fn section_card<R>(ui: &mut egui::Ui, title: &str, body: impl FnOnce(&mut egui::Ui) -> R) -> R {
    let mut out: Option<R> = None;
    Frame::none()
        .fill(ui.visuals().faint_bg_color)
        .rounding(Rounding::same(8.0))
        .stroke(Stroke::new(
            1.0,
            ui.visuals().widgets.noninteractive.bg_stroke.color,
        ))
        .inner_margin(Margin::same(14.0))
        .show(ui, |ui| {
            // Keep all config cards the same visual width.
            ui.set_width(ui.available_width());
            ui.label(RichText::new(title).strong());
            ui.add_space(10.0);
            out = Some(body(ui));
        });
    out.expect("section body")
}

fn mono_block(ui: &mut egui::Ui, text: &str) {
    Frame::none()
        .fill(ui.visuals().extreme_bg_color)
        .inner_margin(Margin::symmetric(10.0, 8.0))
        .rounding(Rounding::same(4.0))
        .show(ui, |ui| {
            ui.label(RichText::new(text).monospace().small());
        });
}

fn path_row(ui: &mut egui::Ui, label: &str, path: &mut String, pick: FilePick) {
    ui.horizontal(|ui| {
        ui.add_sized(
            [132.0, ui.spacing().interact_size.y],
            egui::Label::new(label),
        );
        let browse = 96.0;
        let field_w = (ui.available_width() - browse - 12.0).max(120.0);
        stateful_singleline(ui, path, field_w - 10.0, true);
        if ui.button("Browse…").clicked() {
            let dlg = rfd::FileDialog::new();
            let picked = match pick {
                FilePick::Any => dlg.pick_file(),
                FilePick::Executable => dlg.pick_file(),
            };
            if let Some(p) = picked {
                *path = p.display().to_string();
            }
        }
    });
    ui.add_space(4.0);
}

fn stateful_singleline(ui: &mut egui::Ui, value: &mut String, width: f32, required: bool) {
    let empty = value.trim().is_empty();
    // Single outer stroke only (no Frame stroke — avoids double outline).
    let neutral_outer = Color32::from_rgb(58, 62, 72);
    let empty_hint = Color32::from_rgb(72, 92, 118);

    let mut stroke_width = 1.25;
    let mut stroke_color = if required && empty {
        empty_hint
    } else {
        neutral_outer
    };

    let framed = Frame::none()
        .inner_margin(Margin::symmetric(6.0, 4.0))
        .show(ui, |ui| {
            ui.add_sized(
                egui::vec2(width.max(40.0), ui.spacing().interact_size.y),
                egui::TextEdit::singleline(value).frame(false),
            )
        });

    if framed.response.has_focus() {
        stroke_width = 1.5;
        stroke_color = theme::ACCENT;
    }

    ui.painter().rect_stroke(
        framed.response.rect,
        Rounding::same(4.0),
        Stroke::new(stroke_width, stroke_color),
    );
}
