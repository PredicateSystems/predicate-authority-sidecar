//! Terminal User Interface for the Predicate Authority Sidecar.
//!
//! Provides a real-time dashboard showing authorization decisions,
//! metrics, and system health.

use std::io::{self, Stdout};
use std::time::Duration;

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame, Terminal,
};

use crate::http::AppState;

/// TUI application state
pub struct TuiApp {
    /// Whether the app should quit
    should_quit: bool,
    /// Refresh interval in milliseconds
    refresh_ms: u64,
    /// Reference to the shared application state (cloned, but inner Arc fields are shared)
    app_state: AppState,
    /// Start time for uptime calculation
    start_time: std::time::Instant,
    /// Scroll offset for the event list
    scroll_offset: usize,
    /// Whether the help overlay is visible
    show_help: bool,
    /// Whether updates are paused
    paused: bool,
}

impl TuiApp {
    /// Create a new TUI application
    pub fn new(app_state: AppState, refresh_ms: u64) -> Self {
        Self {
            should_quit: false,
            refresh_ms,
            app_state,
            start_time: std::time::Instant::now(),
            scroll_offset: 0,
            show_help: false,
            paused: false,
        }
    }

    /// Handle keyboard input
    fn handle_key(&mut self, key: KeyCode) {
        // Help overlay takes priority
        if self.show_help {
            match key {
                KeyCode::Char('?') | KeyCode::Esc => {
                    self.show_help = false;
                }
                _ => {}
            }
            return;
        }

        match key {
            // Quit
            KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => {
                self.should_quit = true;
            }
            // Scroll down
            KeyCode::Char('j') | KeyCode::Down => {
                self.scroll_offset = self.scroll_offset.saturating_add(1);
            }
            // Scroll up
            KeyCode::Char('k') | KeyCode::Up => {
                self.scroll_offset = self.scroll_offset.saturating_sub(1);
            }
            // Jump to top
            KeyCode::Char('g') => {
                self.scroll_offset = 0;
            }
            // Jump to bottom
            KeyCode::Char('G') => {
                let event_count = self.app_state.proof_ledger.event_count();
                self.scroll_offset = event_count.saturating_sub(1);
            }
            // Toggle help
            KeyCode::Char('?') => {
                self.show_help = true;
            }
            // Toggle pause
            KeyCode::Char('p') | KeyCode::Char('P') => {
                self.paused = !self.paused;
            }
            _ => {}
        }
    }

    /// Get formatted uptime string
    fn uptime_str(&self) -> String {
        let elapsed = self.start_time.elapsed();
        let secs = elapsed.as_secs();
        let hours = secs / 3600;
        let mins = (secs % 3600) / 60;
        let secs = secs % 60;

        if hours > 0 {
            format!("{}h {:02}m", hours, mins)
        } else if mins > 0 {
            format!("{}m {:02}s", mins, secs)
        } else {
            format!("{}s", secs)
        }
    }
}

/// Setup terminal for TUI mode
fn setup_terminal() -> io::Result<Terminal<CrosstermBackend<Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    Terminal::new(backend)
}

/// Restore terminal to normal mode
fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> io::Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

/// Draw the UI
fn draw_ui(frame: &mut Frame, app: &TuiApp) {
    let size = frame.size();

    // Create main layout: header, body, footer
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(10),   // Body
            Constraint::Length(3), // Footer
        ])
        .split(size);

    // Draw header
    draw_header(frame, chunks[0], app);

    // Draw body (split into left and right panes)
    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(chunks[1]);

    draw_authority_gate(frame, body_chunks[0], app);
    draw_metrics(frame, body_chunks[1], app);

    // Draw footer
    draw_footer(frame, chunks[2], app);

    // Draw help overlay if visible
    if app.show_help {
        draw_help_overlay(frame, size);
    }
}

/// Draw the header bar
fn draw_header(frame: &mut Frame, area: Rect, app: &TuiApp) {
    let version = env!("CARGO_PKG_VERSION");
    let uptime = app.uptime_str();

    // Get stats from app state
    let _stats = app.app_state.proof_ledger.stats();
    let rule_count = app.app_state.policy_engine.rule_count();

    // Status indicator
    let (status_text, status_color) = if app.paused {
        ("PAUSED", Color::Yellow)
    } else {
        ("LIVE", Color::Green)
    };

    let header_text = vec![
        Line::from(vec![
            Span::styled(
                format!("  PREDICATE AUTHORITY v{}  ", version),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("      "),
            Span::styled("MODE: ", Style::default().fg(Color::DarkGray)),
            Span::styled("strict", Style::default().fg(Color::Yellow)),
            Span::raw("  "),
            Span::styled(
                format!("[{}]", status_text),
                Style::default().fg(status_color).add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled("UPTIME: ", Style::default().fg(Color::DarkGray)),
            Span::styled(uptime, Style::default().fg(Color::Green)),
            Span::raw("  "),
            Span::styled("[?:help]", Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(vec![
            Span::styled("  Policy: ", Style::default().fg(Color::DarkGray)),
            Span::styled("loaded", Style::default().fg(Color::Green)),
            Span::raw("                    "),
            Span::styled("Rules: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{} active", rule_count),
                Style::default().fg(Color::White),
            ),
            Span::raw("      "),
            Span::styled("[Q:quit P:pause j/k:scroll]", Style::default().fg(Color::DarkGray)),
        ]),
    ];

    let header = Paragraph::new(header_text).block(
        Block::default()
            .borders(Borders::TOP | Borders::LEFT | Borders::RIGHT)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    frame.render_widget(header, area);
}

/// Draw the live authority gate (left pane)
fn draw_authority_gate(frame: &mut Frame, area: Rect, app: &TuiApp) {
    // Get recent events from the ledger (get more to allow scrolling)
    let recent_events = app.app_state.proof_ledger.recent_events(100);

    let mut lines: Vec<Line> = Vec::new();

    if recent_events.is_empty() {
        lines.push(Line::from(Span::styled(
            "  Waiting for authorization requests...",
            Style::default().fg(Color::DarkGray),
        )));
    } else {
        // Apply scroll offset and limit to visible area
        let visible_count = (area.height.saturating_sub(2) / 4) as usize; // 4 lines per event
        let scroll = app.scroll_offset.min(recent_events.len().saturating_sub(1));
        let visible_events = recent_events.iter().skip(scroll).take(visible_count);

        for event in visible_events {
            let (status, status_style) = if event.allowed {
                (
                    "[ \u{2713} ALLOW ]",
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                (
                    "[ \u{2717} DENY  ]",
                    Style::default()
                        .fg(Color::Red)
                        .add_modifier(Modifier::BOLD),
                )
            };

            // First line: status + agent
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(status, status_style),
                Span::raw(" "),
                Span::styled(&event.principal_id, Style::default().fg(Color::Cyan)),
            ]));

            // Second line: action -> resource
            let action_resource = format!("    {} \u{2192} {}", event.action, event.resource);
            lines.push(Line::from(Span::styled(
                if action_resource.len() > (area.width as usize - 4) {
                    format!(
                        "{}...",
                        &action_resource[..area.width.saturating_sub(7) as usize]
                    )
                } else {
                    action_resource
                },
                Style::default().fg(Color::White),
            )));

            // Third line: mandate_id or reason + latency
            let latency_str = event
                .latency_us
                .map(|us| {
                    if us >= 1000 {
                        format!("{:.1}ms", us as f64 / 1000.0)
                    } else {
                        format!("{}μs", us)
                    }
                })
                .unwrap_or_else(|| "--".to_string());

            let info = if let Some(ref mandate_id) = event.mandate_id {
                format!("    {} | {}", mandate_id, latency_str)
            } else {
                format!("    {} | {}", event.reason, latency_str)
            };
            lines.push(Line::from(Span::styled(
                info,
                Style::default().fg(Color::DarkGray),
            )));

            // Empty line between events
            lines.push(Line::from(""));
        }
    }

    // Show scroll indicator in title if scrolled
    let title = if app.scroll_offset > 0 {
        format!(" LIVE AUTHORITY GATE [{}/{}] ", app.scroll_offset + 1, recent_events.len())
    } else {
        " LIVE AUTHORITY GATE ".to_string()
    };

    let gate = Paragraph::new(lines).block(
        Block::default()
            .title(Span::styled(
                title,
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    frame.render_widget(gate, area);
}

/// Draw the metrics panel (right pane)
fn draw_metrics(frame: &mut Frame, area: Rect, app: &TuiApp) {
    let stats = app.app_state.proof_ledger.stats();
    let total = stats.total_allowed + stats.total_denied;

    let allowed_pct = if total > 0 {
        (stats.total_allowed as f64 / total as f64) * 100.0
    } else {
        0.0
    };
    let denied_pct = if total > 0 {
        (stats.total_denied as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    // Calculate throughput (requests per second)
    let uptime_secs = app.start_time.elapsed().as_secs_f64();
    let throughput_str = if uptime_secs > 0.0 && total > 0 {
        format!("{:.1} req/s", total as f64 / uptime_secs)
    } else {
        "-- req/s".to_string()
    };

    // Calculate average latency
    let avg_latency_str = stats
        .avg_latency_us()
        .map(|us| {
            if us >= 1000 {
                format!("{:.2}ms", us as f64 / 1000.0)
            } else {
                format!("{}μs", us)
            }
        })
        .unwrap_or_else(|| "--".to_string());

    // Estimate tokens saved (rough: ~180 tokens per blocked action)
    let tokens_saved = stats.total_denied * 180;

    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  Total Requests:    ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{:>8}", total),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(vec![
            Span::styled("  \u{251c}\u{2500} Allowed:        ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{:>8}", stats.total_allowed),
                Style::default().fg(Color::Green),
            ),
            Span::styled(
                format!(" ({:.1}%)", allowed_pct),
                Style::default().fg(Color::DarkGray),
            ),
        ]),
        Line::from(vec![
            Span::styled("  \u{2514}\u{2500} Blocked:        ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{:>8}", stats.total_denied),
                Style::default().fg(Color::Red),
            ),
            Span::styled(
                format!(" ({:.1}%)", denied_pct),
                Style::default().fg(Color::DarkGray),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Throughput:        ", Style::default().fg(Color::DarkGray)),
            Span::styled(throughput_str, Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  Avg Latency:       ", Style::default().fg(Color::DarkGray)),
            Span::styled(avg_latency_str, Style::default().fg(Color::White)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(Span::styled(
            "  TOKEN CONTEXT SAVED",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "  \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(vec![
            Span::styled("  Blocked early:     ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{} actions", stats.total_denied),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Est. tokens saved: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("~{}", tokens_saved),
                Style::default().fg(Color::Green),
            ),
        ]),
    ];

    let metrics = Paragraph::new(lines).block(
        Block::default()
            .title(Span::styled(
                " METRICS ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    frame.render_widget(metrics, area);
}

/// Draw the footer bar
fn draw_footer(frame: &mut Frame, area: Rect, app: &TuiApp) {
    let stats = app.app_state.proof_ledger.stats();
    let proof_count = stats.total_allowed + stats.total_denied;

    let footer_text = Line::from(vec![
        Span::raw("  "),
        Span::styled(
            format!("Generated {} proofs this session.", proof_count),
            Style::default().fg(Color::DarkGray),
        ),
        Span::raw(" Run "),
        Span::styled(
            "`predicate login`",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" to sync to vault.", Style::default().fg(Color::DarkGray)),
    ]);

    let footer = Paragraph::new(footer_text).block(
        Block::default()
            .borders(Borders::BOTTOM | Borders::LEFT | Borders::RIGHT)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    frame.render_widget(footer, area);
}

/// Draw the help overlay modal
fn draw_help_overlay(frame: &mut Frame, area: Rect) {
    // Center the help box
    let help_width = 50;
    let help_height = 14;
    let x = (area.width.saturating_sub(help_width)) / 2;
    let y = (area.height.saturating_sub(help_height)) / 2;
    let help_area = Rect::new(x, y, help_width, help_height);

    // Clear the area behind the overlay
    let clear = Block::default().style(Style::default().bg(Color::Black));
    frame.render_widget(clear, help_area);

    let help_text = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  KEYBOARD SHORTCUTS",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Q / Esc    ", Style::default().fg(Color::Yellow)),
            Span::styled("Quit dashboard", Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  j / \u{2193}      ", Style::default().fg(Color::Yellow)),
            Span::styled("Scroll down", Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  k / \u{2191}      ", Style::default().fg(Color::Yellow)),
            Span::styled("Scroll up", Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  g          ", Style::default().fg(Color::Yellow)),
            Span::styled("Jump to newest", Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  G          ", Style::default().fg(Color::Yellow)),
            Span::styled("Jump to oldest", Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  P          ", Style::default().fg(Color::Yellow)),
            Span::styled("Pause/Resume updates", Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  ?          ", Style::default().fg(Color::Yellow)),
            Span::styled("Toggle this help", Style::default().fg(Color::White)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  Press ? or Esc to close",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    let help = Paragraph::new(help_text).block(
        Block::default()
            .title(Span::styled(
                " HELP ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan)),
    );

    frame.render_widget(help, help_area);
}

/// Print session summary after TUI exits
fn print_session_summary(app: &TuiApp) {
    let stats = app.app_state.proof_ledger.stats();
    let total = stats.total_allowed + stats.total_denied;
    let uptime = app.uptime_str();
    let tokens_saved = stats.total_denied * 180;

    let allowed_pct = if total > 0 {
        (stats.total_allowed as f64 / total as f64) * 100.0
    } else {
        0.0
    };
    let denied_pct = if total > 0 {
        (stats.total_denied as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    println!();
    println!("\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}");
    println!("  PREDICATE AUTHORITY SESSION SUMMARY");
    println!("\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}");
    println!("  Duration:         {}", uptime);
    println!("  Total Requests:   {}", total);
    println!(
        "  \u{251c}\u{2500} Allowed:       {} ({:.1}%)",
        stats.total_allowed, allowed_pct
    );
    println!(
        "  \u{2514}\u{2500} Blocked:       {} ({:.1}%)",
        stats.total_denied, denied_pct
    );
    println!();
    println!("  Proofs Generated: {}", total);
    println!("  Est. Tokens Saved: ~{}", tokens_saved);
    println!();
    println!("  To sync proofs to enterprise vault, run:");
    println!("    $ predicate login");
    println!();
    println!("\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}");
}

/// Run the TUI dashboard
///
/// This function takes over the terminal and displays a live dashboard
/// of authorization events and metrics.
///
/// Note: `app_state` is cloned but its internal `Arc` fields are shared,
/// so updates from the HTTP server are visible in real-time.
pub async fn run_dashboard(app_state: AppState, refresh_ms: u64) -> anyhow::Result<()> {
    // Setup terminal
    let mut terminal = setup_terminal()?;

    // Create TUI app
    let mut app = TuiApp::new(app_state, refresh_ms);

    // Run event loop
    let result = run_event_loop(&mut terminal, &mut app).await;

    // Always restore terminal, even on error
    restore_terminal(&mut terminal)?;

    // Print session summary
    print_session_summary(&app);

    result
}

/// Main event loop for the TUI
async fn run_event_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut TuiApp,
) -> anyhow::Result<()> {
    let tick_rate = Duration::from_millis(app.refresh_ms);

    loop {
        // Draw UI
        terminal.draw(|frame| draw_ui(frame, app))?;

        // Check for quit
        if app.should_quit {
            break;
        }

        // Poll for events with timeout
        if event::poll(tick_rate)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    app.handle_key(key.code);
                }
            }
        }
    }

    Ok(())
}
