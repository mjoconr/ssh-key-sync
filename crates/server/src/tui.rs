use std::{io, path::PathBuf, time::Duration};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    style::Print,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::Line,
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph},
};
use ssh_key_sync_core::{Config, signing_key_fingerprint};

use crate::{open_state, state::State};

#[derive(Clone, Copy)]
enum Tab {
    Enrollments,
    Tokens,
    Groups,
}

enum Overlay {
    None,
    Approve(String),
    ConfirmDeny(String),
    ConfirmRevoke(String),
    InstallInput(String),
    InstallCommands(String),
}

struct App {
    config: Config,
    state: State,
    tab: Tab,
    enrollment_index: usize,
    token_index: usize,
    group_index: usize,
    overlay: Overlay,
    message: String,
    public_url: String,
    signing_fingerprint: String,
}

pub(crate) fn run(path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load(path)?;
    let state = open_state(&config)?;
    let public_url = config
        .public_url
        .clone()
        .unwrap_or_else(|| "https://keys.example.net".into());
    let signing_fingerprint = signing_key_fingerprint(&config.signing_key_file)?;
    enable_raw_mode()?;
    execute!(io::stdout(), EnterAlternateScreen)?;
    let result = run_app(App {
        config,
        state,
        tab: Tab::Enrollments,
        enrollment_index: 0,
        token_index: 0,
        group_index: 0,
        overlay: Overlay::None,
        message: String::new(),
        public_url,
        signing_fingerprint,
    });
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen)?;
    result
}

fn run_app(mut app: App) -> Result<(), Box<dyn std::error::Error>> {
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    loop {
        terminal.draw(|frame| draw(frame, &app))?;
        if !event::poll(Duration::from_millis(250))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        if handle_key(&mut app, key.code)? {
            return Ok(());
        }
    }
}

#[allow(clippy::too_many_lines)]
fn handle_key(app: &mut App, code: KeyCode) -> Result<bool, Box<dyn std::error::Error>> {
    match &app.overlay {
        Overlay::Approve(request_id) => {
            let request_id = request_id.clone();
            let groups = app.config.groups.keys().collect::<Vec<_>>();
            match code {
                KeyCode::Esc => app.overlay = Overlay::None,
                KeyCode::Up => app.group_index = app.group_index.saturating_sub(1),
                KeyCode::Down => {
                    app.group_index = (app.group_index + 1).min(groups.len().saturating_sub(1));
                }
                KeyCode::Enter => {
                    if let Some(group) = groups.get(app.group_index) {
                        if app.state.approve(&request_id, group)? {
                            app.message = format!("approved {request_id} into {group}");
                            app.overlay = Overlay::None;
                        }
                    }
                }
                _ => {}
            }
        }
        Overlay::ConfirmDeny(request_id) => match code {
            KeyCode::Char('y') => {
                if app.state.deny(request_id)? {
                    app.message = format!("denied {request_id}");
                }
                app.overlay = Overlay::None;
            }
            KeyCode::Char('n') | KeyCode::Esc => app.overlay = Overlay::None,
            _ => {}
        },
        Overlay::ConfirmRevoke(token_id) => match code {
            KeyCode::Char('y') => {
                if app.state.revoke_token(token_id)? {
                    app.message = format!("revoked {token_id}");
                }
                app.overlay = Overlay::None;
            }
            KeyCode::Char('n') | KeyCode::Esc => app.overlay = Overlay::None,
            _ => {}
        },
        Overlay::InstallInput(hostname) => {
            let mut value = hostname.clone();
            match code {
                KeyCode::Esc => app.overlay = Overlay::None,
                KeyCode::Backspace => {
                    value.pop();
                    app.overlay = Overlay::InstallInput(value);
                }
                KeyCode::Enter if !value.trim().is_empty() => {
                    app.overlay = Overlay::InstallCommands(value);
                }
                KeyCode::Char(c) if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') => {
                    value.push(c);
                    app.overlay = Overlay::InstallInput(value);
                }
                _ => {}
            }
        }
        Overlay::InstallCommands(hostname) => match code {
            KeyCode::Esc | KeyCode::Char('i') => app.overlay = Overlay::None,
            KeyCode::Char('c') => {
                copy_to_clipboard(&app.public_install_command())?;
                app.message = "copied public install command".into();
            }
            KeyCode::Char('p') => {
                copy_to_clipboard(&app.private_install_command(hostname))?;
                app.message = "copied enrollment command".into();
            }
            _ => {}
        },
        Overlay::None => match code {
            KeyCode::Char('q') => return Ok(true),
            KeyCode::Char('i') => app.overlay = Overlay::InstallInput(String::new()),
            KeyCode::Tab => {
                app.tab = match app.tab {
                    Tab::Enrollments => Tab::Tokens,
                    Tab::Tokens => Tab::Groups,
                    Tab::Groups => Tab::Enrollments,
                };
            }
            KeyCode::Up => app.previous(),
            KeyCode::Down => app.next(),
            KeyCode::Char('a') => {
                if matches!(app.tab, Tab::Enrollments) {
                    if let Some(request) = app.selected_pending_enrollment() {
                        app.group_index = 0;
                        app.overlay = Overlay::Approve(request.id.clone());
                    }
                }
            }
            KeyCode::Char('d') => {
                if matches!(app.tab, Tab::Enrollments) {
                    if let Some(request) = app.selected_pending_enrollment() {
                        app.overlay = Overlay::ConfirmDeny(request.id.clone());
                    }
                }
            }
            KeyCode::Char('r') => {
                if matches!(app.tab, Tab::Tokens) {
                    if let Some(token) = app
                        .state
                        .list_tokens()?
                        .into_iter()
                        .filter(|token| token.revoked_at.is_none())
                        .nth(app.token_index)
                    {
                        app.overlay = Overlay::ConfirmRevoke(token.id);
                    }
                }
            }
            _ => {}
        },
    }
    Ok(false)
}

impl App {
    fn public_install_command(&self) -> String {
        format!(
            "curl -fsSL https://github.com/mjoconr/ssh-key-sync/releases/latest/download/install.sh | sudo sh -s -- --server {} --signing-key-sha256 {} --apply-ssh --enable-timer",
            self.public_url, self.signing_fingerprint
        )
    }

    fn private_install_command(&self, hostname: &str) -> String {
        format!(
            "curl -fsSL https://github.com/mjoconr/ssh-key-sync/releases/latest/download/install.sh | sudo sh -s -- --server {} --signing-key-sha256 {} --apply-ssh --enroll {}",
            self.public_url, self.signing_fingerprint, hostname
        )
    }

    fn next(&mut self) {
        match self.tab {
            Tab::Enrollments => {
                let len = self.state.list_enrollments().map_or(0, |items| items.len());
                self.enrollment_index = (self.enrollment_index + 1).min(len.saturating_sub(1));
            }
            Tab::Tokens => {
                let len = self.state.list_tokens().map_or(0, |items| items.len());
                self.token_index = (self.token_index + 1).min(len.saturating_sub(1));
            }
            Tab::Groups => {
                self.group_index =
                    (self.group_index + 1).min(self.config.groups.len().saturating_sub(1));
            }
        }
    }

    fn previous(&mut self) {
        match self.tab {
            Tab::Enrollments => self.enrollment_index = self.enrollment_index.saturating_sub(1),
            Tab::Tokens => self.token_index = self.token_index.saturating_sub(1),
            Tab::Groups => self.group_index = self.group_index.saturating_sub(1),
        }
    }

    fn selected_pending_enrollment(&self) -> Option<crate::state::Enrollment> {
        self.state
            .list_enrollments()
            .ok()?
            .into_iter()
            .filter(|item| item.status == "pending")
            .nth(self.enrollment_index)
    }
}

fn draw(frame: &mut ratatui::Frame<'_>, app: &App) {
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(3),
        ])
        .split(frame.area());
    let title = match app.tab {
        Tab::Enrollments => "Enrollments",
        Tab::Tokens => "Machine Tokens",
        Tab::Groups => "Groups",
    };
    frame.render_widget(
        Paragraph::new(format!(
            " SSH Key Sync | {title} | [Tab] section  [A]pprove  [D]eny  [R]evoke  [Q]uit "
        ))
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL)),
        areas[0],
    );
    match app.tab {
        Tab::Enrollments => draw_enrollments(frame, app, areas[1]),
        Tab::Tokens => draw_tokens(frame, app, areas[1]),
        Tab::Groups => draw_groups(frame, app, areas[1]),
    }
    frame.render_widget(
        Paragraph::new(app.message.as_str()).block(Block::default().borders(Borders::ALL)),
        areas[2],
    );
    match &app.overlay {
        Overlay::Approve(_) => draw_group_picker(frame, app),
        Overlay::ConfirmDeny(id) => draw_confirmation(frame, &format!("Deny {id}? [y/n]")),
        Overlay::ConfirmRevoke(id) => draw_confirmation(frame, &format!("Revoke {id}? [y/n]")),
        Overlay::InstallInput(hostname) => draw_install_input(frame, hostname),
        Overlay::InstallCommands(hostname) => draw_install_commands(frame, app, hostname),
        Overlay::None => {}
    }
}

fn draw_install_input(frame: &mut ratatui::Frame<'_>, hostname: &str) {
    let area = centered(frame.area(), 60, 20);
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(format!(
            "Hostname: {hostname}\n\n[Enter] continue  [Esc] cancel"
        ))
        .block(
            Block::default()
                .title(" Machine Name ")
                .borders(Borders::ALL),
        ),
        area,
    );
}

fn draw_install_commands(frame: &mut ratatui::Frame<'_>, app: &App, hostname: &str) {
    let area = centered(frame.area(), 90, 55);
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(vec![
            Line::from("Public-group install:"),
            Line::from(app.public_install_command()),
            Line::from(""),
            Line::from("Private-group enrollment:"),
            Line::from(app.private_install_command(hostname)),
            Line::from(""),
            Line::from("[c] copy public  [p] copy enrollment  [Esc] close"),
        ])
        .wrap(ratatui::widgets::Wrap { trim: true })
        .block(
            Block::default()
                .title(" Client Install Commands ")
                .borders(Borders::ALL),
        ),
        area,
    );
}

fn copy_to_clipboard(value: &str) -> io::Result<()> {
    execute!(
        io::stdout(),
        Print(format!("\x1b]52;c;{}\x07", STANDARD.encode(value)))
    )
}

fn draw_enrollments(frame: &mut ratatui::Frame<'_>, app: &App, area: Rect) {
    let items = app.state.list_enrollments().unwrap_or_default();
    let rows = items
        .iter()
        .map(|item| {
            ListItem::new(format!(
                "{} {:<8} {:<20} source={}",
                item.code, item.status, item.name, item.source_ip
            ))
        })
        .collect::<Vec<_>>();
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);
    frame.render_widget(
        List::new(rows)
            .block(Block::default().title(" Requests ").borders(Borders::ALL))
            .highlight_style(Style::default().bg(Color::DarkGray))
            .highlight_symbol("> "),
        columns[0],
    );
    let details = items.get(app.enrollment_index).map_or_else(
        || vec![Line::from("No request selected")],
        |item| {
            vec![
                Line::from(format!("ID: {}", item.id)),
                Line::from(format!("Name: {}", item.name)),
                Line::from(format!("Hostname: {}", item.hostname)),
                Line::from(format!("Source: {}", item.source_ip)),
                Line::from(format!("Interfaces: {}", item.local_addresses)),
                Line::from(format!("Status: {}", item.status)),
                Line::from(format!("Group: {}", item.group.as_deref().unwrap_or("-"))),
                Line::from(format!("Expires: {}", item.expires_at)),
            ]
        },
    );
    frame.render_widget(
        Paragraph::new(details).block(Block::default().title(" Details ").borders(Borders::ALL)),
        columns[1],
    );
}

fn draw_tokens(frame: &mut ratatui::Frame<'_>, app: &App, area: Rect) {
    let items = app.state.list_tokens().unwrap_or_default();
    let rows = items
        .iter()
        .map(|item| {
            ListItem::new(format!(
                "{:<28} {:<12} {:<20} {}",
                item.label,
                item.group,
                item.id,
                if item.revoked_at.is_some() {
                    "revoked"
                } else {
                    "active"
                }
            ))
        })
        .collect::<Vec<_>>();
    frame.render_widget(
        List::new(rows)
            .block(Block::default().title(" Tokens ").borders(Borders::ALL))
            .highlight_style(Style::default().bg(Color::DarkGray))
            .highlight_symbol("> "),
        area,
    );
}

fn draw_groups(frame: &mut ratatui::Frame<'_>, app: &App, area: Rect) {
    let rows = app
        .config
        .groups
        .iter()
        .map(|(name, group)| {
            let keys = app.config.keys_for_group(name).map_or(0, |keys| keys.len());
            ListItem::new(format!(
                "{:<20} {:?} keys={} cidrs={}",
                name,
                group.visibility,
                keys,
                group.cidrs.len()
            ))
        })
        .collect::<Vec<_>>();
    frame.render_widget(
        List::new(rows)
            .block(Block::default().title(" Groups ").borders(Borders::ALL))
            .highlight_style(Style::default().bg(Color::DarkGray))
            .highlight_symbol("> "),
        area,
    );
}

fn draw_group_picker(frame: &mut ratatui::Frame<'_>, app: &App) {
    let area = centered(frame.area(), 50, 50);
    let items = app
        .config
        .groups
        .keys()
        .map(|name| ListItem::new(name.as_str()))
        .collect::<Vec<_>>();
    frame.render_widget(Clear, area);
    frame.render_widget(
        List::new(items)
            .block(
                Block::default()
                    .title(" Approve into group: Enter select, Esc cancel ")
                    .borders(Borders::ALL),
            )
            .highlight_style(Style::default().bg(Color::DarkGray))
            .highlight_symbol("> "),
        area,
    );
}

fn draw_confirmation(frame: &mut ratatui::Frame<'_>, message: &str) {
    let area = centered(frame.area(), 50, 20);
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(message).block(Block::default().title(" Confirm ").borders(Borders::ALL)),
        area,
    );
}

fn centered(area: Rect, percent_x: u16, percent_y: u16) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}
