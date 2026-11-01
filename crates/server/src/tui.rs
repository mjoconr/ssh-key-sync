use std::{
    io,
    path::PathBuf,
    time::{Duration, Instant},
};

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
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
};
use ssh_key_sync_core::{Config, parse_public_key, signing_key_fingerprint};

use crate::{
    config_edit, open_state,
    state::{Enrollment, State, TokenRecord},
};

#[derive(Clone, Copy)]
enum Tab {
    Enrollments,
    Tokens,
    Groups,
    Keys,
}

#[derive(Clone)]
struct KeyAddForm {
    owner: String,
    group_index: usize,
    key: String,
    field: usize,
}

#[derive(Clone)]
struct KeyRow {
    owner: String,
    fingerprint: String,
    groups: Vec<String>,
}

#[derive(Clone)]
enum Overlay {
    None,
    Approve {
        request_id: String,
        replacement_for: Option<String>,
    },
    ConfirmDeny(String),
    ConfirmRevoke(String),
    ConfirmHideEnrollment(String),
    ConfirmRetire(String),
    ConfirmHideToken(String),
    HostInput {
        value: String,
        replacement_for: Option<String>,
    },
    HostGuide {
        hostname: String,
        replacement_for: Option<String>,
    },
    GroupAdd {
        name: String,
        public: bool,
    },
    ConfirmGroupRemove(String),
    CidrManager {
        group: String,
        index: usize,
    },
    CidrInput {
        group: String,
        value: String,
    },
    ConfirmCidrRemove {
        group: String,
        cidr: String,
    },
    KeyAdd(KeyAddForm),
    AssignKey {
        owner: String,
        group_index: usize,
    },
    ConfirmKeyRemove {
        owner: String,
        fingerprint: String,
    },
    Audit {
        title: String,
        lines: Vec<String>,
    },
}

struct App {
    config_path: PathBuf,
    config: Config,
    state: State,
    tab: Tab,
    enrollment_index: usize,
    token_index: usize,
    group_index: usize,
    key_index: usize,
    overlay: Overlay,
    message: String,
    public_url: String,
    signing_fingerprint: String,
    replacement_for: Option<String>,
    pending_count: usize,
    pending_checked: Instant,
}

pub(crate) fn run(path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load(&path)?;
    let state = open_state(&config)?;
    let public_url = config
        .public_url
        .clone()
        .unwrap_or_else(|| "https://keys.example.net".into());
    let signing_fingerprint = signing_key_fingerprint(&config.signing_key_file)?;
    let pending_count = state
        .list_enrollments()?
        .into_iter()
        .filter(|item| item.status == "pending")
        .count();
    enable_raw_mode()?;
    execute!(io::stdout(), EnterAlternateScreen)?;
    let result = run_app(App {
        config_path: path,
        config,
        state,
        tab: Tab::Enrollments,
        enrollment_index: 0,
        token_index: 0,
        group_index: 0,
        key_index: 0,
        overlay: Overlay::None,
        message: if pending_count == 0 {
            "No pending enrollment requests".into()
        } else {
            format!("{pending_count} pending enrollment request(s)")
        },
        public_url,
        signing_fingerprint,
        replacement_for: None,
        pending_count,
        pending_checked: Instant::now(),
    });
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen)?;
    result
}

fn run_app(mut app: App) -> Result<(), Box<dyn std::error::Error>> {
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    loop {
        app.notify_new_requests()?;
        terminal.draw(|frame| draw(frame, &app))?;
        if !event::poll(Duration::from_millis(250))? {
            continue;
        }
        match event::read()? {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                if handle_key(&mut app, key.code)? {
                    return Ok(());
                }
            }
            Event::Paste(text) => handle_paste(&mut app, &text),
            _ => {}
        }
    }
}

#[allow(clippy::too_many_lines)]
fn handle_key(app: &mut App, code: KeyCode) -> Result<bool, Box<dyn std::error::Error>> {
    let overlay = app.overlay.clone();
    match overlay {
        Overlay::Approve {
            request_id,
            replacement_for,
        } => {
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
                            app.enrollment_index = 0;
                            app.message = replacement_for.map_or_else(
                                || format!("approved {request_id} into {group}"),
                                |old| {
                                    format!(
                                        "approved {request_id} into {group}; verify the new SSH session, then retire {old}"
                                    )
                                },
                            );
                            app.overlay = Overlay::None;
                        }
                    }
                }
                _ => {}
            }
        }
        Overlay::ConfirmDeny(request_id) => match code {
            KeyCode::Char('y' | 'Y') => {
                if app.state.deny(&request_id)? {
                    app.message = format!("denied {request_id}");
                    app.enrollment_index = 0;
                }
                app.overlay = Overlay::None;
            }
            KeyCode::Char('n' | 'N') | KeyCode::Esc => app.overlay = Overlay::None,
            _ => {}
        },
        Overlay::ConfirmRevoke(token_id) => match code {
            KeyCode::Char('y' | 'Y') => {
                if app.state.revoke_token(&token_id)? {
                    app.message = format!("revoked {token_id}");
                    app.token_index = 0;
                }
                app.overlay = Overlay::None;
            }
            KeyCode::Char('n' | 'N') | KeyCode::Esc => app.overlay = Overlay::None,
            _ => {}
        },
        Overlay::ConfirmHideEnrollment(request_id) => match code {
            KeyCode::Char('y' | 'Y') => {
                if app.state.hide_enrollment(&request_id)? {
                    app.message = format!("hid request {request_id}");
                    app.enrollment_index = 0;
                }
                app.overlay = Overlay::None;
            }
            KeyCode::Char('n' | 'N') | KeyCode::Esc => app.overlay = Overlay::None,
            _ => {}
        },
        Overlay::ConfirmRetire(request_id) => match code {
            KeyCode::Char('y' | 'Y') => {
                if app.state.retire_enrollment(&request_id)? {
                    app.message = format!("retired request and token {request_id}");
                    app.enrollment_index = 0;
                    if app.replacement_for.as_deref() == Some(&request_id) {
                        app.replacement_for = None;
                    }
                }
                app.overlay = Overlay::None;
            }
            KeyCode::Char('n' | 'N') | KeyCode::Esc => app.overlay = Overlay::None,
            _ => {}
        },
        Overlay::ConfirmHideToken(token_id) => match code {
            KeyCode::Char('y' | 'Y') => {
                if app.state.hide_token(&token_id)? {
                    app.message = format!("hid token {token_id}");
                    app.token_index = 0;
                }
                app.overlay = Overlay::None;
            }
            KeyCode::Char('n' | 'N') | KeyCode::Esc => app.overlay = Overlay::None,
            _ => {}
        },
        Overlay::HostInput {
            mut value,
            replacement_for,
        } => match code {
            KeyCode::Esc => app.overlay = Overlay::None,
            KeyCode::Backspace => {
                value.pop();
                app.overlay = Overlay::HostInput {
                    value,
                    replacement_for,
                };
            }
            KeyCode::Enter if !value.trim().is_empty() => {
                app.overlay = Overlay::HostGuide {
                    hostname: value,
                    replacement_for,
                };
            }
            KeyCode::Char(c) if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':') => {
                value.push(c);
                app.overlay = Overlay::HostInput {
                    value,
                    replacement_for,
                };
            }
            _ => {}
        },
        Overlay::HostGuide {
            hostname,
            replacement_for,
        } => match code {
            KeyCode::Esc | KeyCode::Char('i' | 'I') => app.overlay = Overlay::None,
            KeyCode::Char('c' | 'C') => {
                copy_to_clipboard(&app.public_install_command())?;
                app.message = "copied public install command".into();
                app.enrollment_index = 0;
                app.overlay = Overlay::None;
            }
            KeyCode::Char('p' | 'P') => {
                copy_to_clipboard(&app.private_install_command(&hostname))?;
                app.enrollment_index = 0;
                app.replacement_for = replacement_for;
                app.message = "copied enrollment command; waiting for the request to appear".into();
                app.overlay = Overlay::None;
            }
            _ => {}
        },
        Overlay::GroupAdd {
            mut name,
            mut public,
        } => match code {
            KeyCode::Esc => app.overlay = Overlay::None,
            KeyCode::Backspace => {
                name.pop();
                app.overlay = Overlay::GroupAdd { name, public };
            }
            KeyCode::Char(' ') => {
                public = !public;
                app.overlay = Overlay::GroupAdd { name, public };
            }
            KeyCode::Enter if !name.trim().is_empty() => {
                let added = name.trim().to_owned();
                match app.config_edit(|editor| editor.add_group(added.clone(), public)) {
                    Ok(()) => {
                        app.message = format!("added {} group {added}", visibility(public));
                        app.overlay = Overlay::None;
                    }
                    Err(error) => app.message = error.to_string(),
                }
            }
            KeyCode::Char(c) if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') => {
                name.push(c);
                app.overlay = Overlay::GroupAdd { name, public };
            }
            _ => {}
        },
        Overlay::ConfirmGroupRemove(name) => match code {
            KeyCode::Char('y' | 'Y') => {
                match app.config_edit(|editor| editor.remove_group(&name)) {
                    Ok(()) => app.message = format!("removed group {name}"),
                    Err(error) => app.message = error.to_string(),
                }
                app.overlay = Overlay::None;
            }
            KeyCode::Char('n' | 'N') | KeyCode::Esc => app.overlay = Overlay::None,
            _ => {}
        },
        Overlay::CidrManager { group, mut index } => {
            let cidrs = app
                .config
                .groups
                .get(&group)
                .map_or_else(Vec::new, |item| item.cidrs.clone());
            match code {
                KeyCode::Esc => app.overlay = Overlay::None,
                KeyCode::Up => {
                    index = index.saturating_sub(1);
                    app.overlay = Overlay::CidrManager { group, index };
                }
                KeyCode::Down => {
                    index = (index + 1).min(cidrs.len().saturating_sub(1));
                    app.overlay = Overlay::CidrManager { group, index };
                }
                KeyCode::Char('a' | 'A' | 'n' | 'N') => {
                    app.overlay = Overlay::CidrInput {
                        group,
                        value: String::new(),
                    };
                }
                KeyCode::Char('d' | 'D' | 'x' | 'X') => {
                    if let Some(cidr) = cidrs.get(index) {
                        app.overlay = Overlay::ConfirmCidrRemove {
                            group,
                            cidr: cidr.to_string(),
                        };
                    }
                }
                _ => {}
            }
        }
        Overlay::CidrInput { group, mut value } => match code {
            KeyCode::Esc => {
                app.overlay = Overlay::CidrManager { group, index: 0 };
            }
            KeyCode::Backspace => {
                value.pop();
                app.overlay = Overlay::CidrInput { group, value };
            }
            KeyCode::Enter if !value.trim().is_empty() => {
                match app.config_edit(|editor| editor.add_cidr(&group, value.trim())) {
                    Ok(()) => {
                        app.message = format!("added {} to {group}", value.trim());
                        app.overlay = Overlay::None;
                    }
                    Err(error) => app.message = error.to_string(),
                }
            }
            KeyCode::Char(c) if c.is_ascii_hexdigit() || matches!(c, ':' | '.' | '/') => {
                value.push(c);
                app.overlay = Overlay::CidrInput { group, value };
            }
            _ => {}
        },
        Overlay::ConfirmCidrRemove { group, cidr } => match code {
            KeyCode::Char('y' | 'Y') => {
                match app.config_edit(|editor| editor.remove_cidr(&group, &cidr)) {
                    Ok(()) => app.message = format!("removed {cidr} from {group}"),
                    Err(error) => app.message = error.to_string(),
                }
                app.overlay = Overlay::None;
            }
            KeyCode::Char('n' | 'N') | KeyCode::Esc => {
                app.overlay = Overlay::CidrManager { group, index: 0 };
            }
            _ => {}
        },
        Overlay::KeyAdd(mut form) => {
            let groups = app.config.groups.keys().collect::<Vec<_>>();
            match code {
                KeyCode::Esc => app.overlay = Overlay::None,
                KeyCode::Up => {
                    form.field = form.field.saturating_sub(1);
                    app.overlay = Overlay::KeyAdd(form);
                }
                KeyCode::Down => {
                    form.field = (form.field + 1).min(2);
                    app.overlay = Overlay::KeyAdd(form);
                }
                KeyCode::Left if form.field == 1 => {
                    form.group_index = form.group_index.saturating_sub(1);
                    app.overlay = Overlay::KeyAdd(form);
                }
                KeyCode::Right if form.field == 1 => {
                    form.group_index = (form.group_index + 1).min(groups.len().saturating_sub(1));
                    app.overlay = Overlay::KeyAdd(form);
                }
                KeyCode::Backspace => {
                    if form.field == 0 {
                        form.owner.pop();
                    } else if form.field == 2 {
                        form.key.pop();
                    }
                    app.overlay = Overlay::KeyAdd(form);
                }
                KeyCode::Enter if form.field < 2 => {
                    if form.field == 0 && form.owner.trim().is_empty() {
                        app.message = "key owner is required".into();
                    } else if form.field == 1 && groups.is_empty() {
                        app.message = "create a group before adding a key".into();
                    } else {
                        form.field += 1;
                        app.overlay = Overlay::KeyAdd(form);
                    }
                }
                KeyCode::Enter if !form.owner.trim().is_empty() && !form.key.trim().is_empty() => {
                    if let Some(group) = groups.get(form.group_index) {
                        let owner = form.owner.trim().to_owned();
                        let group = (*group).clone();
                        let key = form.key.trim().to_owned();
                        match app.config_edit(|editor| editor.add_key(&owner, &group, &key)) {
                            Ok(()) => {
                                app.message = format!("added key for {owner} in {group}");
                                app.overlay = Overlay::None;
                            }
                            Err(error) => app.message = error.to_string(),
                        }
                    }
                }
                KeyCode::Char(c) if form.field == 0 => {
                    if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '@') {
                        form.owner.push(c);
                        app.overlay = Overlay::KeyAdd(form);
                    }
                }
                KeyCode::Char(c) if form.field == 2 && c >= ' ' => {
                    form.key.push(c);
                    app.overlay = Overlay::KeyAdd(form);
                }
                _ => {}
            }
        }
        Overlay::AssignKey {
            owner,
            mut group_index,
        } => {
            let groups = app.config.groups.keys().cloned().collect::<Vec<_>>();
            match code {
                KeyCode::Esc => app.overlay = Overlay::None,
                KeyCode::Up => {
                    group_index = group_index.saturating_sub(1);
                    app.overlay = Overlay::AssignKey { owner, group_index };
                }
                KeyCode::Down => {
                    group_index = (group_index + 1).min(groups.len().saturating_sub(1));
                    app.overlay = Overlay::AssignKey { owner, group_index };
                }
                KeyCode::Enter => {
                    if let Some(group) = groups.get(group_index) {
                        let assigned = app
                            .config
                            .keys
                            .get(&owner)
                            .is_some_and(|entry| entry.groups.contains(group));
                        match app.config_edit(|editor| editor.assign_key(&owner, group, !assigned))
                        {
                            Ok(()) => {
                                app.message = format!(
                                    "{} {owner} {} {group}",
                                    if assigned { "removed" } else { "assigned" },
                                    if assigned { "from" } else { "to" }
                                );
                                app.overlay = Overlay::None;
                            }
                            Err(error) => app.message = error.to_string(),
                        }
                    }
                }
                _ => {}
            }
        }
        Overlay::ConfirmKeyRemove { owner, fingerprint } => match code {
            KeyCode::Char('y' | 'Y') => {
                match app.config_edit(|editor| editor.remove_key(&owner, &fingerprint)) {
                    Ok(()) => {
                        app.message = format!("removed {fingerprint} from {owner}");
                        app.key_index = 0;
                    }
                    Err(error) => app.message = error.to_string(),
                }
                app.overlay = Overlay::None;
            }
            KeyCode::Char('n' | 'N') | KeyCode::Esc => app.overlay = Overlay::None,
            _ => {}
        },
        Overlay::Audit { .. } => match code {
            KeyCode::Esc | KeyCode::Char('v' | 'V') => app.overlay = Overlay::None,
            _ => {}
        },
        Overlay::None => {
            if matches!(code, KeyCode::Char('q' | 'Q')) {
                return Ok(true);
            }
            if matches!(code, KeyCode::F(5)) {
                match app.reload_config() {
                    Ok(()) => app.message = "configuration refreshed".into(),
                    Err(error) => app.message = error.to_string(),
                }
                return Ok(false);
            }
            if matches!(code, KeyCode::Char('i' | 'I')) {
                app.enrollment_index = 0;
                app.overlay = Overlay::HostInput {
                    value: String::new(),
                    replacement_for: None,
                };
                return Ok(false);
            }
            match code {
                KeyCode::Tab => {
                    app.tab = match app.tab {
                        Tab::Enrollments => Tab::Tokens,
                        Tab::Tokens => Tab::Groups,
                        Tab::Groups => Tab::Keys,
                        Tab::Keys => Tab::Enrollments,
                    };
                }
                KeyCode::Up => app.previous(),
                KeyCode::Down => app.next(),
                KeyCode::Char('a' | 'A') => app.primary_action(),
                KeyCode::Char('d' | 'D') => app.deny_selected(),
                KeyCode::Char('r' | 'R') => app.revoke_selected(),
                KeyCode::Char('x' | 'X') => app.remove_selected()?,
                KeyCode::Char('c' | 'C') => app.open_cidrs(),
                KeyCode::Char('g' | 'G') => app.assign_selected(),
                KeyCode::Char('p' | 'P') => app.start_replacement(),
                KeyCode::Char('v' | 'V') => app.open_audit()?,
                _ => {}
            }
        }
    }
    Ok(false)
}

fn handle_paste(app: &mut App, text: &str) {
    let overlay = app.overlay.clone();
    match overlay {
        Overlay::HostInput {
            mut value,
            replacement_for,
        } => {
            value.extend(
                text.chars()
                    .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':')),
            );
            app.overlay = Overlay::HostInput {
                value,
                replacement_for,
            };
        }
        Overlay::GroupAdd { mut name, public } => {
            name.extend(
                text.chars()
                    .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')),
            );
            app.overlay = Overlay::GroupAdd { name, public };
        }
        Overlay::CidrInput { group, mut value } => {
            value.extend(
                text.chars()
                    .filter(|c| c.is_ascii_hexdigit() || matches!(c, ':' | '.' | '/')),
            );
            app.overlay = Overlay::CidrInput { group, value };
        }
        Overlay::KeyAdd(mut form) => {
            match form.field {
                0 => {
                    form.owner.extend(text.chars().filter(|c| {
                        c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '@')
                    }));
                }
                2 => {
                    if let Some(line) = text.lines().find(|line| !line.trim().is_empty()) {
                        form.key.push_str(line.trim());
                    }
                }
                _ => {}
            }
            app.overlay = Overlay::KeyAdd(form);
        }
        _ => {}
    }
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

    fn reload_config(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let config = Config::load(&self.config_path)?;
        self.signing_fingerprint = signing_key_fingerprint(&config.signing_key_file)?;
        self.public_url = config
            .public_url
            .clone()
            .unwrap_or_else(|| "https://keys.example.net".into());
        self.config = config;
        self.group_index = self
            .group_index
            .min(self.config.groups.len().saturating_sub(1));
        self.key_index = self.key_index.min(self.key_rows().len().saturating_sub(1));
        Ok(())
    }

    fn config_edit<F>(&mut self, action: F) -> Result<(), Box<dyn std::error::Error>>
    where
        F: FnOnce(&mut config_edit::Editor) -> Result<(), Box<dyn std::error::Error>>,
    {
        let mut editor = config_edit::Editor::open(&self.config_path)?;
        action(&mut editor)?;
        self.reload_config()
    }

    fn notify_new_requests(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.pending_checked.elapsed() < Duration::from_secs(2) {
            return Ok(());
        }
        self.pending_checked = Instant::now();
        let pending = self
            .state
            .list_enrollments()?
            .into_iter()
            .filter(|item| item.status == "pending")
            .count();
        if pending > self.pending_count {
            execute!(io::stdout(), Print("\x07"))?;
            self.message = format!("new enrollment request; {pending} pending. Press A to review");
        }
        self.pending_count = pending;
        Ok(())
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
            Tab::Keys => {
                self.key_index = (self.key_index + 1).min(self.key_rows().len().saturating_sub(1));
            }
        }
    }

    fn previous(&mut self) {
        match self.tab {
            Tab::Enrollments => self.enrollment_index = self.enrollment_index.saturating_sub(1),
            Tab::Tokens => self.token_index = self.token_index.saturating_sub(1),
            Tab::Groups => self.group_index = self.group_index.saturating_sub(1),
            Tab::Keys => self.key_index = self.key_index.saturating_sub(1),
        }
    }

    fn selected_enrollment(&self) -> Option<Enrollment> {
        self.state
            .list_enrollments()
            .ok()?
            .into_iter()
            .nth(self.enrollment_index)
    }

    fn selected_token(&self) -> Option<TokenRecord> {
        self.state
            .list_tokens()
            .ok()?
            .into_iter()
            .nth(self.token_index)
    }

    fn selected_group(&self) -> Option<&str> {
        self.config
            .groups
            .keys()
            .nth(self.group_index)
            .map(String::as_str)
    }

    fn selected_key(&self) -> Option<KeyRow> {
        self.key_rows().into_iter().nth(self.key_index)
    }

    fn key_rows(&self) -> Vec<KeyRow> {
        self.config
            .keys
            .iter()
            .flat_map(|(owner, entry)| {
                entry.keys.iter().filter_map(|key| {
                    parse_public_key(key).ok().map(|parsed| KeyRow {
                        owner: owner.clone(),
                        fingerprint: parsed.fingerprint,
                        groups: entry.groups.clone(),
                    })
                })
            })
            .collect()
    }

    fn primary_action(&mut self) {
        match self.tab {
            Tab::Enrollments => {
                if let Some(request) = self.selected_enrollment() {
                    if request.status == "pending" {
                        self.group_index = 0;
                        self.overlay = Overlay::Approve {
                            request_id: request.id,
                            replacement_for: self.replacement_for.clone(),
                        };
                    } else {
                        self.message = "selected request has already been decided".into();
                    }
                }
            }
            Tab::Groups => {
                self.overlay = Overlay::GroupAdd {
                    name: String::new(),
                    public: false,
                };
            }
            Tab::Keys => {
                if self.config.groups.is_empty() {
                    self.message = "create a group before adding a key".into();
                } else {
                    self.overlay = Overlay::KeyAdd(KeyAddForm {
                        owner: String::new(),
                        group_index: 0,
                        key: String::new(),
                        field: 0,
                    });
                }
            }
            Tab::Tokens => {}
        }
    }

    fn deny_selected(&mut self) {
        if matches!(self.tab, Tab::Enrollments) {
            if let Some(request) = self.selected_enrollment() {
                if request.status == "pending" {
                    self.overlay = Overlay::ConfirmDeny(request.id);
                }
            }
        }
    }

    fn revoke_selected(&mut self) {
        if matches!(self.tab, Tab::Tokens) {
            if let Some(token) = self.selected_token() {
                if token.revoked_at.is_none() {
                    self.overlay = Overlay::ConfirmRevoke(token.id);
                }
            }
        }
    }

    fn remove_selected(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        match self.tab {
            Tab::Enrollments => {
                if let Some(request) = self.selected_enrollment() {
                    self.overlay = if request.status == "approved" {
                        Overlay::ConfirmRetire(request.id)
                    } else if request.status == "pending" {
                        self.message = "deny the pending request before hiding it".into();
                        Overlay::None
                    } else {
                        Overlay::ConfirmHideEnrollment(request.id)
                    };
                }
            }
            Tab::Tokens => {
                if let Some(token) = self.selected_token() {
                    if token.revoked_at.is_some() {
                        self.overlay = Overlay::ConfirmHideToken(token.id);
                    } else {
                        self.message = "revoke the token before hiding it".into();
                    }
                }
            }
            Tab::Groups => {
                if let Some(group) = self.selected_group().map(str::to_owned) {
                    if self.state.group_has_active_tokens(&group)? {
                        self.message =
                            format!("group {group} has active machine tokens; retire them first");
                    } else {
                        self.overlay = Overlay::ConfirmGroupRemove(group);
                    }
                }
            }
            Tab::Keys => {
                if let Some(key) = self.selected_key() {
                    self.overlay = Overlay::ConfirmKeyRemove {
                        owner: key.owner,
                        fingerprint: key.fingerprint,
                    };
                }
            }
        }
        Ok(())
    }

    fn open_cidrs(&mut self) {
        if matches!(self.tab, Tab::Groups) {
            if let Some(group) = self.selected_group().map(str::to_owned) {
                self.overlay = Overlay::CidrManager { group, index: 0 };
            }
        }
    }

    fn assign_selected(&mut self) {
        if matches!(self.tab, Tab::Keys) {
            if let Some(key) = self.selected_key() {
                self.group_index = 0;
                self.overlay = Overlay::AssignKey {
                    owner: key.owner,
                    group_index: 0,
                };
            }
        }
    }

    fn start_replacement(&mut self) {
        if matches!(self.tab, Tab::Enrollments) {
            if let Some(request) = self.selected_enrollment() {
                if request.status == "approved" {
                    self.overlay = Overlay::HostInput {
                        value: String::new(),
                        replacement_for: Some(request.id),
                    };
                    self.message = "enter the new hostname; keep the current session open".into();
                } else {
                    self.message = "replacement starts from an approved enrollment".into();
                }
            }
        }
    }

    fn open_audit(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let (title, subject) = match self.tab {
            Tab::Enrollments => self
                .selected_enrollment()
                .map(|item| (format!("Audit: {}", item.name), item.id)),
            Tab::Tokens => self
                .selected_token()
                .map(|item| (format!("Audit: {}", item.label), item.id)),
            Tab::Groups | Tab::Keys => None,
        }
        .map_or((String::new(), None), |(title, subject)| {
            (title, Some(subject))
        });
        if subject.is_none() {
            self.message = "select an enrollment or token to inspect its audit trail".into();
            return Ok(());
        }
        let lines = self
            .state
            .list_audit(subject.as_deref())?
            .into_iter()
            .map(|item| {
                format!(
                    "{} {} {}: {}",
                    item.created_at, item.action, item.subject, item.details
                )
            })
            .collect();
        self.overlay = Overlay::Audit { title, lines };
        Ok(())
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
        Tab::Keys => "Public Keys",
    };
    frame.render_widget(
        Paragraph::new(format!(
            " SSH Key Sync | {title} | pending={} | [Tab]section [I]nstall [F5]refresh [Q]uit ",
            app.pending_count
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
        Tab::Keys => draw_keys(frame, app, areas[1]),
    }
    frame.render_widget(
        Paragraph::new(app.message.as_str())
            .wrap(Wrap { trim: true })
            .block(Block::default().borders(Borders::ALL)),
        areas[2],
    );
    match &app.overlay {
        Overlay::Approve {
            replacement_for, ..
        } => draw_group_picker(
            frame,
            app,
            replacement_for.as_ref().map_or(
                " Approve into group: Enter select, Esc cancel ",
                |_| " Approve replacement into group: Enter select, Esc cancel ",
            ),
        ),
        Overlay::ConfirmDeny(id) => draw_confirmation(frame, &format!("Deny {id}? [y/n]")),
        Overlay::ConfirmRevoke(id) => draw_confirmation(frame, &format!("Revoke {id}? [y/n]")),
        Overlay::ConfirmHideEnrollment(id) => {
            draw_confirmation(frame, &format!("Hide request {id}? [y/n]"));
        }
        Overlay::ConfirmRetire(id) => {
            draw_confirmation(
                frame,
                &format!("Retire request and revoke token {id}? [y/n]"),
            );
        }
        Overlay::ConfirmHideToken(id) => {
            draw_confirmation(frame, &format!("Hide revoked token {id}? [y/n]"));
        }
        Overlay::HostInput {
            value,
            replacement_for,
        } => draw_host_input(frame, value, replacement_for.as_deref()),
        Overlay::HostGuide {
            hostname,
            replacement_for,
        } => draw_host_guide(frame, app, hostname, replacement_for.as_deref()),
        Overlay::GroupAdd { name, public } => draw_group_input(frame, name, *public),
        Overlay::ConfirmGroupRemove(name) => {
            draw_confirmation(frame, &format!("Remove group {name}? [y/n]"));
        }
        Overlay::CidrManager { group, index } => draw_cidrs(frame, app, group, *index),
        Overlay::CidrInput { group, value } => draw_cidr_input(frame, group, value),
        Overlay::ConfirmCidrRemove { group, cidr } => {
            draw_confirmation(frame, &format!("Remove {cidr} from {group}? [y/n]"));
        }
        Overlay::KeyAdd(form) => draw_key_input(frame, app, form),
        Overlay::AssignKey { owner, group_index } => {
            draw_assignment_picker(frame, app, owner, *group_index);
        }
        Overlay::ConfirmKeyRemove { owner, fingerprint } => {
            draw_confirmation(frame, &format!("Remove {fingerprint} from {owner}? [y/n]"));
        }
        Overlay::Audit { title, lines } => draw_audit(frame, title, lines),
        Overlay::None => {}
    }
}

fn draw_host_input(frame: &mut ratatui::Frame<'_>, hostname: &str, replacing: Option<&str>) {
    let area = centered(frame.area(), 65, 24);
    frame.render_widget(Clear, area);
    let text = replacing.map_or_else(
        || {
            format!(
                "Hostname: {hostname}\n\nEnter continues. Esc cancels."
            )
        },
        |old| {
            format!(
                "Replacing: {old}\nNew hostname: {hostname}\n\nEnter continues. Keep the current SSH session open."
            )
        },
    );
    frame.render_widget(
        Paragraph::new(text).block(
            Block::default()
                .title(" Machine Name ")
                .borders(Borders::ALL),
        ),
        area,
    );
}

fn draw_host_guide(
    frame: &mut ratatui::Frame<'_>,
    app: &App,
    hostname: &str,
    replacing: Option<&str>,
) {
    let area = centered(frame.area(), 94, 62);
    frame.render_widget(Clear, area);
    let mut lines = vec![
        Line::from("Public-group install:"),
        Line::from(app.public_install_command()),
        Line::from(""),
        Line::from("Private-group enrollment:"),
        Line::from(app.private_install_command(hostname)),
        Line::from(""),
    ];
    if let Some(old) = replacing {
        lines.extend([
            Line::from(format!("Replacement flow for {old}:")),
            Line::from("1. Copy and run the enrollment command."),
            Line::from("2. Return here when the new row appears and press A."),
            Line::from("3. Choose the group and verify a new SSH session."),
            Line::from("4. Select the old enrollment and press X to retire it."),
            Line::from(""),
        ]);
    }
    lines.push(Line::from(
        "[c] copy public  [p] copy enrollment  [Esc] close",
    ));
    frame.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: true }).block(
            Block::default()
                .title(" Client Install Commands ")
                .borders(Borders::ALL),
        ),
        area,
    );
}

fn draw_group_input(frame: &mut ratatui::Frame<'_>, name: &str, public: bool) {
    let area = centered(frame.area(), 60, 24);
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(format!(
            "Name: {name}\nVisibility: {}\n\n[Space] toggle visibility  [Enter] add  [Esc] cancel",
            visibility(public)
        ))
        .block(Block::default().title(" Add Group ").borders(Borders::ALL)),
        area,
    );
}

fn draw_cidrs(frame: &mut ratatui::Frame<'_>, app: &App, group: &str, selected: usize) {
    let area = centered(frame.area(), 70, 55);
    frame.render_widget(Clear, area);
    let cidrs = app
        .config
        .groups
        .get(group)
        .map_or_else(Vec::new, |item| item.cidrs.clone());
    let rows = if cidrs.is_empty() {
        vec![ListItem::new("No CIDRs configured")]
    } else {
        cidrs
            .iter()
            .map(|cidr| ListItem::new(cidr.to_string()))
            .collect()
    };
    let mut state = ListState::default();
    state.select((!cidrs.is_empty()).then_some(selected.min(cidrs.len().saturating_sub(1))));
    frame.render_stateful_widget(
        List::new(rows)
            .block(
                Block::default()
                    .title(format!(" {group} CIDRs "))
                    .borders(Borders::ALL),
            )
            .highlight_style(Style::default().bg(Color::DarkGray))
            .highlight_symbol("> "),
        area,
        &mut state,
    );
    let footer = Rect {
        x: area.x,
        y: area.bottom().saturating_sub(2),
        width: area.width,
        height: 2,
    };
    frame.render_widget(
        Paragraph::new("[A]dd [D]elete [Esc]close").style(Style::default().fg(Color::Cyan)),
        footer,
    );
}

fn draw_cidr_input(frame: &mut ratatui::Frame<'_>, group: &str, value: &str) {
    let area = centered(frame.area(), 65, 22);
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(format!(
            "Group: {group}\nCIDR: {value}\n\n[Enter] add  [Esc] back"
        ))
        .block(Block::default().title(" Add CIDR ").borders(Borders::ALL)),
        area,
    );
}

fn draw_key_input(frame: &mut ratatui::Frame<'_>, app: &App, form: &KeyAddForm) {
    let area = centered(frame.area(), 94, 62);
    frame.render_widget(Clear, area);
    let group = app
        .config
        .groups
        .keys()
        .nth(form.group_index)
        .map_or("-", String::as_str);
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(format!("{}Owner: {}", focus(form.field == 0), form.owner)),
            Line::from(format!(
                "{}Group: {group}  [Left/Right changes]",
                focus(form.field == 1)
            )),
            Line::from(format!("{}Public key:", focus(form.field == 2))),
            Line::from(form.key.as_str()),
            Line::from(""),
            Line::from("[Enter] next/add  [Up/Down] field  paste is accepted  [Esc] cancel"),
        ])
        .wrap(Wrap { trim: true })
        .block(
            Block::default()
                .title(" Add Public Key ")
                .borders(Borders::ALL),
        ),
        area,
    );
}

fn draw_assignment_picker(frame: &mut ratatui::Frame<'_>, app: &App, owner: &str, selected: usize) {
    let area = centered(frame.area(), 60, 60);
    frame.render_widget(Clear, area);
    let items = app
        .config
        .groups
        .keys()
        .map(|group| {
            let assigned = app
                .config
                .keys
                .get(owner)
                .is_some_and(|entry| entry.groups.contains(group));
            ListItem::new(format!("[{}] {group}", if assigned { "x" } else { " " }))
        })
        .collect::<Vec<_>>();
    let mut state = ListState::default();
    state.select((!items.is_empty()).then_some(selected));
    frame.render_stateful_widget(
        List::new(items)
            .block(
                Block::default()
                    .title(format!(" {owner} groups: Enter toggles, Esc closes "))
                    .borders(Borders::ALL),
            )
            .highlight_style(Style::default().bg(Color::DarkGray))
            .highlight_symbol("> "),
        area,
        &mut state,
    );
}

fn draw_audit(frame: &mut ratatui::Frame<'_>, title: &str, lines: &[String]) {
    let area = centered(frame.area(), 94, 70);
    frame.render_widget(Clear, area);
    let body = if lines.is_empty() {
        "No audit records".to_owned()
    } else {
        let mut body = lines.join("\n");
        body.push_str("\n\n[Esc] close");
        body
    };
    frame.render_widget(
        Paragraph::new(body).wrap(Wrap { trim: true }).block(
            Block::default()
                .title(format!(" {title} "))
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
    let columns = split_details(area);
    let mut state = ListState::default();
    let selected = app.enrollment_index.min(items.len().saturating_sub(1));
    state.select((!items.is_empty()).then_some(selected));
    frame.render_stateful_widget(
        List::new(rows)
            .block(
                Block::default()
                    .title(" Requests | [A]pprove [D]eny [P]replace [X]hide/retire [V]audit ")
                    .borders(Borders::ALL),
            )
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("> "),
        columns[0],
        &mut state,
    );
    let details = items.get(selected).map_or_else(
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
                "{:<24} {:<14} {:<8}",
                item.label,
                item.group,
                if item.revoked_at.is_some() {
                    "revoked"
                } else {
                    "active"
                }
            ))
        })
        .collect::<Vec<_>>();
    let columns = split_details(area);
    let mut state = ListState::default();
    let selected = app.token_index.min(items.len().saturating_sub(1));
    state.select((!items.is_empty()).then_some(selected));
    frame.render_stateful_widget(
        List::new(rows)
            .block(
                Block::default()
                    .title(" Tokens | [R]evoke [X]hide [V]audit ")
                    .borders(Borders::ALL),
            )
            .highlight_style(Style::default().bg(Color::DarkGray))
            .highlight_symbol("> "),
        columns[0],
        &mut state,
    );
    let details = items.get(selected).map_or_else(
        || vec![Line::from("No token selected")],
        |item| {
            vec![
                Line::from(format!("ID: {}", item.id)),
                Line::from(format!("Label: {}", item.label)),
                Line::from(format!("Group: {}", item.group)),
                Line::from(format!("Created: {}", item.created_at)),
                Line::from(format!(
                    "Revoked: {}",
                    item.revoked_at
                        .map_or_else(|| "-".into(), |value| value.to_string())
                )),
                Line::from(format!(
                    "Last used: {}",
                    item.last_used_at
                        .map_or_else(|| "-".into(), |value| value.to_string())
                )),
                Line::from(format!(
                    "Last source: {}",
                    item.last_source_ip.as_deref().unwrap_or("-")
                )),
                Line::from(format!(
                    "Client: {}",
                    item.last_client_version.as_deref().unwrap_or("-")
                )),
            ]
        },
    );
    frame.render_widget(
        Paragraph::new(details).block(Block::default().title(" Details ").borders(Borders::ALL)),
        columns[1],
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
                "{:<20} {:<7} keys={} cidrs={}",
                name,
                visibility(group.visibility == ssh_key_sync_core::Visibility::Public),
                keys,
                group.cidrs.len()
            ))
        })
        .collect::<Vec<_>>();
    let columns = split_details(area);
    let mut state = ListState::default();
    state.select((!app.config.groups.is_empty()).then_some(app.group_index));
    frame.render_stateful_widget(
        List::new(rows)
            .block(
                Block::default()
                    .title(" Groups | [A]dd [C]IDRs [X]remove ")
                    .borders(Borders::ALL),
            )
            .highlight_style(Style::default().bg(Color::DarkGray))
            .highlight_symbol("> "),
        columns[0],
        &mut state,
    );
    let details = app
        .selected_group()
        .and_then(|name| app.config.groups.get(name).map(|group| (name, group)))
        .map_or_else(
            || vec![Line::from("No group selected")],
            |(name, group)| {
                let mut lines = vec![
                    Line::from(format!("Name: {name}")),
                    Line::from(
                        "Visibility: ".to_owned()
                            + visibility(group.visibility == ssh_key_sync_core::Visibility::Public),
                    ),
                    Line::from(format!(
                        "Keys: {}",
                        app.config.keys_for_group(name).map_or(0, |keys| keys.len())
                    )),
                    Line::from("CIDRs:"),
                ];
                if group.cidrs.is_empty() {
                    lines.push(Line::from("  -"));
                } else {
                    lines.extend(
                        group
                            .cidrs
                            .iter()
                            .map(|cidr| Line::from(format!("  {cidr}"))),
                    );
                }
                lines
            },
        );
    frame.render_widget(
        Paragraph::new(details).block(Block::default().title(" Details ").borders(Borders::ALL)),
        columns[1],
    );
}

fn draw_keys(frame: &mut ratatui::Frame<'_>, app: &App, area: Rect) {
    let items = app.key_rows();
    let rows = items
        .iter()
        .map(|item| {
            ListItem::new(format!(
                "{:<18} {}",
                item.owner,
                item.fingerprint.trim_start_matches("SHA256:")
            ))
        })
        .collect::<Vec<_>>();
    let columns = split_details(area);
    let mut state = ListState::default();
    let selected = app.key_index.min(items.len().saturating_sub(1));
    state.select((!items.is_empty()).then_some(selected));
    frame.render_stateful_widget(
        List::new(rows)
            .block(
                Block::default()
                    .title(" Keys | [A]dd [G]roups [X]remove ")
                    .borders(Borders::ALL),
            )
            .highlight_style(Style::default().bg(Color::DarkGray))
            .highlight_symbol("> "),
        columns[0],
        &mut state,
    );
    let details = items.get(selected).map_or_else(
        || vec![Line::from("No key selected")],
        |item| {
            vec![
                Line::from(format!("Owner: {}", item.owner)),
                Line::from(format!("Fingerprint: {}", item.fingerprint)),
                Line::from(format!("Groups: {}", item.groups.join(", "))),
            ]
        },
    );
    frame.render_widget(
        Paragraph::new(details)
            .wrap(Wrap { trim: true })
            .block(Block::default().title(" Details ").borders(Borders::ALL)),
        columns[1],
    );
}

fn draw_group_picker(frame: &mut ratatui::Frame<'_>, app: &App, title: &str) {
    let area = centered(frame.area(), 50, 50);
    let items = app
        .config
        .groups
        .keys()
        .map(|name| ListItem::new(name.as_str()))
        .collect::<Vec<_>>();
    frame.render_widget(Clear, area);
    let mut state = ListState::default();
    state.select((!items.is_empty()).then_some(app.group_index));
    frame.render_stateful_widget(
        List::new(items)
            .block(Block::default().title(title).borders(Borders::ALL))
            .highlight_style(Style::default().bg(Color::DarkGray))
            .highlight_symbol("> "),
        area,
        &mut state,
    );
}

fn draw_confirmation(frame: &mut ratatui::Frame<'_>, message: &str) {
    let area = centered(frame.area(), 55, 20);
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(message).block(Block::default().title(" Confirm ").borders(Borders::ALL)),
        area,
    );
}

fn split_details(area: Rect) -> std::rc::Rc<[Rect]> {
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(area)
}

fn focus(active: bool) -> &'static str {
    if active { "> " } else { "  " }
}

fn visibility(public: bool) -> &'static str {
    if public { "public" } else { "private" }
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
