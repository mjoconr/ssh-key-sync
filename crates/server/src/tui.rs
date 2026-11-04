use std::{
    cmp::Ordering,
    collections::BTreeSet,
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
use ssh_key_sync_core::{
    Config, parse_public_key, public_key_algorithm, signing_key_fingerprint, unix_now,
};

use crate::{
    config_edit, open_state, sanitize_metadata,
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
    algorithm: String,
    fingerprint: String,
    groups: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EnrollmentFilter {
    All,
    Pending,
    Approved,
    Denied,
    Conflicted,
}

impl EnrollmentFilter {
    const fn label(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Conflicted => "conflicted",
        }
    }

    const fn next(self) -> Self {
        match self {
            Self::All => Self::Pending,
            Self::Pending => Self::Approved,
            Self::Approved => Self::Denied,
            Self::Denied => Self::Conflicted,
            Self::Conflicted => Self::All,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EnrollmentSort {
    Newest,
    Oldest,
    Name,
    Status,
    Group,
}

impl EnrollmentSort {
    const fn label(self) -> &'static str {
        match self {
            Self::Newest => "newest",
            Self::Oldest => "oldest",
            Self::Name => "name",
            Self::Status => "status",
            Self::Group => "group",
        }
    }

    const fn next(self) -> Self {
        match self {
            Self::Newest => Self::Oldest,
            Self::Oldest => Self::Name,
            Self::Name => Self::Status,
            Self::Status => Self::Group,
            Self::Group => Self::Newest,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EnrollmentGrouping {
    None,
    Group,
    Status,
}

impl EnrollmentGrouping {
    const fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Group => "group",
            Self::Status => "status",
        }
    }

    const fn next(self) -> Self {
        match self {
            Self::None => Self::Group,
            Self::Group => Self::Status,
            Self::Status => Self::None,
        }
    }
}

#[derive(Clone, Debug)]
struct EnrollmentControls {
    search: String,
    filter: EnrollmentFilter,
    sort: EnrollmentSort,
    grouping: EnrollmentGrouping,
}

impl Default for EnrollmentControls {
    fn default() -> Self {
        Self {
            search: String::new(),
            filter: EnrollmentFilter::All,
            sort: EnrollmentSort::Newest,
            grouping: EnrollmentGrouping::None,
        }
    }
}

#[derive(Clone)]
enum EnrollmentRow {
    Header(String),
    Item(Enrollment),
}

struct EnrollmentView {
    rows: Vec<EnrollmentRow>,
    count: usize,
    total: usize,
}

impl EnrollmentView {
    fn item(&self, index: usize) -> Option<&Enrollment> {
        self.rows
            .iter()
            .filter_map(|row| match row {
                EnrollmentRow::Header(_) => None,
                EnrollmentRow::Item(item) => Some(item),
            })
            .nth(index)
    }

    fn row_for_item(&self, index: usize) -> Option<usize> {
        self.rows
            .iter()
            .enumerate()
            .filter(|(_, row)| matches!(row, EnrollmentRow::Item(_)))
            .nth(index)
            .map(|(position, _)| position)
    }
}

#[derive(Clone)]
enum Overlay {
    None,
    EnrollmentSearch {
        value: String,
    },
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
        auto_update: bool,
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
    enrollment_controls: EnrollmentControls,
    token_index: usize,
    group_index: usize,
    key_index: usize,
    overlay: Overlay,
    message: String,
    public_url: String,
    auto_update: bool,
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
    let auto_update = config.default_auto_update;
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
        enrollment_controls: EnrollmentControls::default(),
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
        auto_update,
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
        Overlay::EnrollmentSearch { mut value } => match code {
            KeyCode::Esc => app.overlay = Overlay::None,
            KeyCode::Backspace => {
                value.pop();
                app.overlay = Overlay::EnrollmentSearch { value };
            }
            KeyCode::Enter => {
                value.trim().clone_into(&mut app.enrollment_controls.search);
                app.enrollment_index = 0;
                app.message = if app.enrollment_controls.search.is_empty() {
                    "enrollment search cleared".into()
                } else {
                    format!("enrollment search: {}", app.enrollment_controls.search)
                };
                app.overlay = Overlay::None;
            }
            KeyCode::Char(c) if !c.is_control() => {
                value.push(c);
                app.overlay = Overlay::EnrollmentSearch { value };
            }
            _ => {}
        },
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
                        let conflicts = app
                            .state
                            .enrollment_by_id(&request_id)?
                            .map_or_else(Vec::new, |request| {
                                app.state.enrollment_conflicts(&request).unwrap_or_default()
                            });
                        if !conflicts.is_empty() && replacement_for.is_none() {
                            let ids = conflicts
                                .iter()
                                .map(|item| item.code.as_str())
                                .collect::<Vec<_>>()
                                .join(",");
                            app.message =
                                format!("active identity conflict: {ids}; use P replacement flow");
                            app.overlay = Overlay::None;
                            return Ok(false);
                        }
                        let expires_at = app
                            .config
                            .groups
                            .get(group.as_str())
                            .and_then(|entry| entry.token_ttl_days)
                            .map(|days| unix_now().saturating_add(days.saturating_mul(86_400)));
                        if app.state.approve(&request_id, group, expires_at)? {
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
                    auto_update: app.auto_update,
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
            auto_update,
        } => match code {
            KeyCode::Esc | KeyCode::Char('i' | 'I') => app.overlay = Overlay::None,
            KeyCode::Char('u' | 'U') => {
                app.auto_update = !auto_update;
                app.overlay = Overlay::HostGuide {
                    hostname,
                    replacement_for,
                    auto_update: app.auto_update,
                };
            }
            KeyCode::Char('c' | 'C') => {
                copy_to_clipboard(&app.public_install_command(auto_update))?;
                app.message = "copied public install command".into();
                app.enrollment_index = 0;
                app.overlay = Overlay::None;
            }
            KeyCode::Char('p' | 'P') => {
                copy_to_clipboard(&app.private_install_command(&hostname, auto_update))?;
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
                match app.config_edit(|editor| editor.add_group(&added, public)) {
                    Ok(()) => {
                        app.tab = Tab::Keys;
                        app.key_index = 0;
                        app.message = if app.config.keys.is_empty() {
                            format!(
                                "added {} group {added}; no key owners exist, press A to add one",
                                visibility(public)
                            )
                        } else {
                            format!(
                                "added {} group {added}; select a key owner and press G to assign it",
                                visibility(public)
                            )
                        };
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
                KeyCode::Char('/') if matches!(app.tab, Tab::Enrollments) => {
                    app.overlay = Overlay::EnrollmentSearch {
                        value: app.enrollment_controls.search.clone(),
                    };
                }
                KeyCode::Char('f' | 'F') if matches!(app.tab, Tab::Enrollments) => {
                    app.enrollment_controls.filter = app.enrollment_controls.filter.next();
                    app.enrollment_index = 0;
                    app.message = format!(
                        "enrollment filter: {}",
                        app.enrollment_controls.filter.label()
                    );
                }
                KeyCode::Char('s' | 'S') if matches!(app.tab, Tab::Enrollments) => {
                    app.enrollment_controls.sort = app.enrollment_controls.sort.next();
                    app.enrollment_index = 0;
                    app.message =
                        format!("enrollment sort: {}", app.enrollment_controls.sort.label());
                }
                KeyCode::Char('b' | 'B') if matches!(app.tab, Tab::Enrollments) => {
                    app.enrollment_controls.grouping = app.enrollment_controls.grouping.next();
                    app.enrollment_index = 0;
                    app.message = format!(
                        "enrollment grouping: {}",
                        app.enrollment_controls.grouping.label()
                    );
                }
                KeyCode::Char('a' | 'A') => app.primary_action(),
                KeyCode::Char('d' | 'D') => app.deny_selected(),
                KeyCode::Char('r' | 'R') => app.revoke_selected(),
                KeyCode::Char('x' | 'X') => app.remove_selected()?,
                KeyCode::Char('c' | 'C') => app.open_cidrs(),
                KeyCode::Char('g' | 'G') => app.assign_selected(),
                KeyCode::Char('l' | 'L') => app.toggle_legacy_xmlrpc(),
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
        Overlay::EnrollmentSearch { mut value } => {
            value.extend(text.chars().filter(|c| !c.is_control()));
            app.overlay = Overlay::EnrollmentSearch { value };
        }
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
    fn public_install_command(&self, auto_update: bool) -> String {
        if let Some(bootstrap_url) = &self.config.bootstrap_url {
            return format!(
                "curl -fsSL {} | sudo sh -s -- --server {} --signing-key-sha256 {} --apply-ssh --enable-timer{}",
                bootstrap_url,
                self.public_url,
                self.signing_fingerprint,
                if auto_update {
                    " --enable-auto-update"
                } else {
                    ""
                }
            );
        }
        format!(
            "curl -fsSL https://github.com/mjoconr/ssh-key-sync/releases/latest/download/install.sh | sudo sh -s -- --server {} --signing-key-sha256 {} --apply-ssh --enable-timer{}",
            self.public_url,
            self.signing_fingerprint,
            if auto_update {
                " --enable-auto-update"
            } else {
                ""
            }
        )
    }

    fn private_install_command(&self, hostname: &str, auto_update: bool) -> String {
        if let Some(bootstrap_url) = &self.config.bootstrap_url {
            return format!(
                "curl -fsSL {} | sudo sh -s -- --server {} --signing-key-sha256 {} --apply-ssh --enroll {}{}",
                bootstrap_url,
                self.public_url,
                self.signing_fingerprint,
                hostname,
                if auto_update {
                    " --enable-auto-update"
                } else {
                    ""
                }
            );
        }
        format!(
            "curl -fsSL https://github.com/mjoconr/ssh-key-sync/releases/latest/download/install.sh | sudo sh -s -- --server {} --signing-key-sha256 {} --apply-ssh --enroll {}{}",
            self.public_url,
            self.signing_fingerprint,
            hostname,
            if auto_update {
                " --enable-auto-update"
            } else {
                ""
            }
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

    fn enrollment_view(&self) -> EnrollmentView {
        let items = self.state.list_enrollments().unwrap_or_default();
        let conflicted = items
            .iter()
            .filter(|item| {
                self.state
                    .enrollment_conflicts(item)
                    .is_ok_and(|conflicts| !conflicts.is_empty())
            })
            .map(|item| item.id.clone())
            .collect();
        build_enrollment_view(items, &self.enrollment_controls, &conflicted)
    }

    fn next(&mut self) {
        match self.tab {
            Tab::Enrollments => {
                let len = self.enrollment_view().count;
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
        self.enrollment_view().item(self.enrollment_index).cloned()
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
                        algorithm: public_key_algorithm(key).unwrap_or_else(|_| "unknown".into()),
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

    fn toggle_legacy_xmlrpc(&mut self) {
        if matches!(self.tab, Tab::Groups) {
            if let Some(group) = self.selected_group().map(str::to_owned) {
                let enabled = self
                    .config
                    .groups
                    .get(&group)
                    .is_some_and(|entry| !entry.legacy_xmlrpc);
                match self.config_edit(|editor| editor.set_legacy_xmlrpc(&group, enabled)) {
                    Ok(()) => {
                        self.message = format!(
                            "{} legacy XML-RPC for {group}",
                            if enabled { "enabled" } else { "disabled" }
                        );
                    }
                    Err(error) => self.message = error.to_string(),
                }
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

fn build_enrollment_view(
    mut items: Vec<Enrollment>,
    controls: &EnrollmentControls,
    conflicted: &BTreeSet<String>,
) -> EnrollmentView {
    let total = items.len();
    let search = controls.search.trim().to_lowercase();
    items.retain(|item| {
        let matches_filter = match controls.filter {
            EnrollmentFilter::All => true,
            EnrollmentFilter::Pending => item.status == "pending",
            EnrollmentFilter::Approved => item.status == "approved",
            EnrollmentFilter::Denied => item.status == "denied",
            EnrollmentFilter::Conflicted => conflicted.contains(&item.id),
        };
        matches_filter && (search.is_empty() || enrollment_matches_search(item, &search))
    });

    if controls.grouping == EnrollmentGrouping::None {
        items.sort_by(|left, right| compare_enrollments(left, right, controls.sort));
    } else {
        items.sort_by(|left, right| {
            enrollment_group_key(left, controls.grouping)
                .cmp(&enrollment_group_key(right, controls.grouping))
                .then_with(|| compare_enrollments(left, right, controls.sort))
        });
    }

    let count = items.len();
    let mut rows = Vec::with_capacity(count.saturating_add(8));
    let mut current_group = None;
    for item in items {
        if controls.grouping != EnrollmentGrouping::None {
            let group = enrollment_group_key(&item, controls.grouping);
            if current_group.as_deref() != Some(group.as_str()) {
                rows.push(EnrollmentRow::Header(group.clone()));
                current_group = Some(group);
            }
        }
        rows.push(EnrollmentRow::Item(item));
    }

    EnrollmentView { rows, count, total }
}

fn enrollment_matches_search(item: &Enrollment, search: &str) -> bool {
    [
        item.code.as_str(),
        item.name.as_str(),
        item.hostname.as_str(),
        item.local_addresses.as_str(),
        item.source_ip.as_str(),
        item.status.as_str(),
        item.group.as_deref().unwrap_or("-"),
    ]
    .iter()
    .any(|value| value.to_lowercase().contains(search))
}

fn enrollment_group_key(item: &Enrollment, grouping: EnrollmentGrouping) -> String {
    match grouping {
        EnrollmentGrouping::None => String::new(),
        EnrollmentGrouping::Group => item
            .group
            .as_deref()
            .filter(|group| !group.is_empty())
            .unwrap_or("(ungrouped)")
            .to_lowercase(),
        EnrollmentGrouping::Status => item.status.to_lowercase(),
    }
}

fn compare_enrollments(left: &Enrollment, right: &Enrollment, sort: EnrollmentSort) -> Ordering {
    let left_name = left.name.to_lowercase();
    let right_name = right.name.to_lowercase();
    match sort {
        EnrollmentSort::Newest => right
            .created_at
            .cmp(&left.created_at)
            .then_with(|| left_name.cmp(&right_name)),
        EnrollmentSort::Oldest => left
            .created_at
            .cmp(&right.created_at)
            .then_with(|| left_name.cmp(&right_name)),
        EnrollmentSort::Name => left_name.cmp(&right_name),
        EnrollmentSort::Status => enrollment_status_rank(&left.status)
            .cmp(&enrollment_status_rank(&right.status))
            .then_with(|| left_name.cmp(&right_name)),
        EnrollmentSort::Group => enrollment_group_key(left, EnrollmentGrouping::Group)
            .cmp(&enrollment_group_key(right, EnrollmentGrouping::Group))
            .then_with(|| left_name.cmp(&right_name)),
    }
}

fn enrollment_status_rank(status: &str) -> u8 {
    match status {
        "pending" => 0,
        "approved" => 1,
        "denied" => 2,
        _ => 3,
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
    draw_header(frame, app, areas[0]);
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
        Overlay::EnrollmentSearch { value } => draw_enrollment_search(frame, value),
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
            auto_update,
        } => draw_host_guide(
            frame,
            app,
            hostname,
            replacement_for.as_deref(),
            *auto_update,
        ),
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

fn draw_enrollment_search(frame: &mut ratatui::Frame<'_>, value: &str) {
    let area = centered(frame.area(), 72, 18);
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(format!(
            "Search: {value}\n\nMatches code, name, hostname, source IP, local addresses,\nstatus and group.\n\n[Enter] apply  [Esc] cancel"
        ))
        .wrap(Wrap { trim: true })
        .block(
            Block::default()
                .title(" Search Enrollments ")
                .borders(Borders::ALL),
        ),
        area,
    );
}

fn draw_header(frame: &mut ratatui::Frame<'_>, app: &App, area: Rect) {
    let title = match app.tab {
        Tab::Enrollments => "Enrollments",
        Tab::Tokens => "Machine Tokens",
        Tab::Groups => "Groups",
        Tab::Keys => "Public Keys",
    };
    let now = unix_now();
    let stale_tokens = app.state.list_tokens().map_or(0, |items| {
        items
            .iter()
            .filter(|item| {
                item.check_in(now, app.config.stale_after_hours)
                    .needs_attention()
            })
            .count()
    });
    frame.render_widget(
        Paragraph::new(format!(
            " SSH Key Sync | {title} | pending={} stale={} | [Tab]section [I]nstall [F5]refresh [Q]uit ",
            app.pending_count, stale_tokens
        ))
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL)),
        area,
    );
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
    auto_update: bool,
) {
    let area = centered(frame.area(), 94, 62);
    frame.render_widget(Clear, area);
    let mut lines = vec![
        Line::from("Public-group install:"),
        Line::from(app.public_install_command(auto_update)),
        Line::from(""),
        Line::from("Private-group enrollment:"),
        Line::from(app.private_install_command(hostname, auto_update)),
        Line::from(""),
    ];
    if app.config.bootstrap_url.is_none() {
        lines.push(Line::from(
            "No bootstrap_url configured: fresh installations require manual release-verifier setup.",
        ));
        lines.push(Line::from(""));
    }
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
    lines.push(Line::from(format!(
        "[u] auto-update {}  [c] copy public  [p] copy enrollment  [Esc] close",
        if auto_update { "ON" } else { "OFF" }
    )));
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

fn draw_enrollment_controls(
    frame: &mut ratatui::Frame<'_>,
    app: &App,
    view: &EnrollmentView,
    area: Rect,
) {
    let search = if app.enrollment_controls.search.is_empty() {
        "-".to_owned()
    } else {
        format!(
            "\"{}\"",
            sanitize_metadata(&app.enrollment_controls.search, 128)
        )
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(format!(
                " Showing {} of {} | [/] Search: {} | [F] Filter: {}",
                view.count,
                view.total,
                search,
                app.enrollment_controls.filter.label()
            )),
            Line::from(format!(
                " [S] Sort: {} | [B] Group by: {}",
                app.enrollment_controls.sort.label(),
                app.enrollment_controls.grouping.label()
            )),
        ])
        .block(Block::default().borders(Borders::BOTTOM)),
        area,
    );
}

fn enrollment_list_items(view: &EnrollmentView) -> Vec<ListItem<'static>> {
    let rows = view
        .rows
        .iter()
        .map(|row| match row {
            EnrollmentRow::Header(name) => ListItem::new(Line::from(format!(
                ":: {} ::",
                sanitize_metadata(name, 128)
            )))
            .style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            EnrollmentRow::Item(item) => {
                let style = match item.status.as_str() {
                    "pending" => Style::default().fg(Color::Yellow),
                    "approved" => Style::default().fg(Color::Green),
                    "denied" => Style::default().fg(Color::Red),
                    _ => Style::default(),
                };
                ListItem::new(format!(
                    "{} {:<8} {:<20} source={}",
                    sanitize_metadata(&item.code, 16),
                    sanitize_metadata(&item.status, 16),
                    sanitize_metadata(&item.name, 128),
                    sanitize_metadata(&item.source_ip, 64)
                ))
                .style(style)
            }
        })
        .collect::<Vec<_>>();
    if rows.is_empty() {
        vec![ListItem::new(
            "No enrollments match the active search and filter",
        )]
    } else {
        rows
    }
}

fn enrollment_detail_lines(app: &App, item: &Enrollment) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(format!("ID: {}", sanitize_metadata(&item.id, 128))),
        Line::from(format!("Name: {}", sanitize_metadata(&item.name, 128))),
        Line::from(format!(
            "Hostname: {}",
            sanitize_metadata(&item.hostname, 255)
        )),
        Line::from(format!(
            "Source: {}",
            sanitize_metadata(&item.source_ip, 64)
        )),
        Line::from(format!(
            "Interfaces: {}",
            sanitize_metadata(&item.local_addresses, 4096)
        )),
        Line::from(format!("Status: {}", sanitize_metadata(&item.status, 16))),
        Line::from(format!(
            "Group: {}",
            sanitize_metadata(item.group.as_deref().unwrap_or("-"), 128)
        )),
        Line::from(format!("Expires: {}", item.expires_at)),
    ];
    let conflicts = app.state.enrollment_conflicts(item).unwrap_or_default();
    if conflicts.is_empty() {
        lines.push(Line::from("Identity conflicts: none"));
    } else {
        lines.push(Line::from(format!(
            "Identity conflicts: {} (use P replacement)",
            conflicts
                .iter()
                .map(|item| sanitize_metadata(&item.code, 16))
                .collect::<Vec<_>>()
                .join(",")
        )));
    }
    lines
}

fn draw_enrollments(frame: &mut ratatui::Frame<'_>, app: &App, area: Rect) {
    let view = app.enrollment_view();
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(5)])
        .split(area);
    draw_enrollment_controls(frame, app, &view, layout[0]);

    let columns = split_details(layout[1]);
    let mut state = ListState::default();
    let selected = app.enrollment_index.min(view.count.saturating_sub(1));
    state.select(view.row_for_item(selected));
    frame.render_stateful_widget(
        List::new(enrollment_list_items(&view))
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
    let details = view.item(selected).map_or_else(
        || vec![Line::from("No request selected")],
        |item| enrollment_detail_lines(app, item),
    );
    frame.render_widget(
        Paragraph::new(details).block(Block::default().title(" Details ").borders(Borders::ALL)),
        columns[1],
    );
}

fn draw_tokens(frame: &mut ratatui::Frame<'_>, app: &App, area: Rect) {
    let items = app.state.list_tokens().unwrap_or_default();
    let now = unix_now();
    let stale_after_hours = app.config.stale_after_hours;
    let rows = items
        .iter()
        .map(|item| {
            ListItem::new(format!(
                "{:<24} {:<14} {:<15}",
                sanitize_metadata(&item.label, 255),
                sanitize_metadata(&item.group, 128),
                item.check_in(now, stale_after_hours).label()
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
            let check_in = item.check_in(now, stale_after_hours);
            let last_check_in = item.last_check_in_at();
            vec![
                Line::from(format!("ID: {}", sanitize_metadata(&item.id, 128))),
                Line::from(format!("Label: {}", sanitize_metadata(&item.label, 255))),
                Line::from(format!("Group: {}", sanitize_metadata(&item.group, 128))),
                Line::from(format!("Check-in: {}", check_in.label())),
                Line::from(format!(
                    "Last check-in: {last_check_in} ({} ago)",
                    format_age(now.saturating_sub(last_check_in))
                )),
                Line::from(format!("Stale after: {stale_after_hours}h")),
                Line::from(format!("Created: {}", item.created_at)),
                Line::from(format!(
                    "Expires: {}",
                    item.expires_at
                        .map_or_else(|| "-".into(), |value| value.to_string())
                )),
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
                    sanitize_metadata(item.last_source_ip.as_deref().unwrap_or("-"), 64)
                )),
                Line::from(format!(
                    "Client: {}",
                    sanitize_metadata(item.last_client_version.as_deref().unwrap_or("-"), 128)
                )),
            ]
        },
    );
    frame.render_widget(
        Paragraph::new(details).block(Block::default().title(" Details ").borders(Borders::ALL)),
        columns[1],
    );
}

fn format_age(seconds: u64) -> String {
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3_600 {
        format!("{}m", seconds / 60)
    } else if seconds < 86_400 {
        format!("{}h", seconds / 3_600)
    } else {
        format!("{}d", seconds / 86_400)
    }
}

fn draw_groups(frame: &mut ratatui::Frame<'_>, app: &App, area: Rect) {
    let rows = app
        .config
        .groups
        .iter()
        .map(|(name, group)| {
            let keys = app.config.keys_for_group(name).map_or(0, |keys| keys.len());
            ListItem::new(format!(
                "{:<20} {:<7} keys={} cidrs={} legacy={}",
                name,
                visibility(group.visibility == ssh_key_sync_core::Visibility::Public),
                keys,
                group.cidrs.len(),
                if group.legacy_xmlrpc { "yes" } else { "no" }
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
                    .title(" Groups | [A]dd [C]IDRs [L]egacy [X]remove ")
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
                    Line::from(format!(
                        "Legacy XML-RPC: {}",
                        if group.legacy_xmlrpc { "yes" } else { "no" }
                    )),
                    Line::from(format!(
                        "Token TTL: {}",
                        group
                            .token_ttl_days
                            .map_or_else(|| "never".into(), |days| format!("{days} days"))
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
                "{:<12} {:<24} {}",
                sanitize_metadata(&item.owner, 128),
                sanitize_metadata(&item.algorithm, 64),
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
                Line::from(format!("Owner: {}", sanitize_metadata(&item.owner, 128))),
                Line::from(format!("Type: {}", sanitize_metadata(&item.algorithm, 64))),
                Line::from(format!(
                    "Fingerprint: {}",
                    sanitize_metadata(&item.fingerprint, 128)
                )),
                Line::from(format!(
                    "Groups: {}",
                    sanitize_metadata(&item.groups.join(", "), 1024)
                )),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn enrollment(
        id: &str,
        name: &str,
        group: Option<&str>,
        status: &str,
        source_ip: &str,
        local_addresses: &str,
        created_at: u64,
    ) -> Enrollment {
        Enrollment {
            id: id.into(),
            code: id.to_ascii_uppercase(),
            name: name.into(),
            hostname: name.into(),
            local_addresses: local_addresses.into(),
            source_ip: source_ip.into(),
            status: status.into(),
            group: group.map(str::to_owned),
            created_at,
            expires_at: created_at + 900,
        }
    }

    fn fixture() -> Vec<Enrollment> {
        vec![
            enrollment(
                "db",
                "db",
                Some("oeg"),
                "approved",
                "203.33.246.98",
                r#"["ens18:10.50.1.50"]"#,
                20,
            ),
            enrollment(
                "mail",
                "mail.jazmin.net.au",
                Some("home"),
                "pending",
                "103.127.123.224",
                r#"["ens18:103.127.123.224"]"#,
                30,
            ),
            enrollment(
                "fax",
                "fax",
                Some("oeg"),
                "denied",
                "103.127.123.203",
                r#"["ens18:103.127.123.203"]"#,
                10,
            ),
        ]
    }

    #[test]
    fn enrollment_search_matches_identity_fields_case_insensitively() {
        let controls = EnrollmentControls {
            search: "JAZMIN".into(),
            ..EnrollmentControls::default()
        };
        let view = build_enrollment_view(fixture(), &controls, &BTreeSet::new());
        assert_eq!(view.count, 1);
        assert_eq!(view.item(0).map(|item| item.id.as_str()), Some("mail"));

        let controls = EnrollmentControls {
            search: "10.50.1".into(),
            ..EnrollmentControls::default()
        };
        let view = build_enrollment_view(fixture(), &controls, &BTreeSet::new());
        assert_eq!(view.item(0).map(|item| item.id.as_str()), Some("db"));
    }

    #[test]
    fn enrollment_filter_and_conflict_search_combine() {
        let controls = EnrollmentControls {
            filter: EnrollmentFilter::Conflicted,
            search: "mail".into(),
            ..EnrollmentControls::default()
        };
        let conflicted = BTreeSet::from(["mail".to_owned()]);
        let view = build_enrollment_view(fixture(), &controls, &conflicted);
        assert_eq!(view.count, 1);
        assert_eq!(view.item(0).map(|item| item.id.as_str()), Some("mail"));
    }

    #[test]
    fn enrollment_grouping_adds_headers_and_skips_them_for_selection() {
        let controls = EnrollmentControls {
            sort: EnrollmentSort::Name,
            grouping: EnrollmentGrouping::Group,
            ..EnrollmentControls::default()
        };
        let view = build_enrollment_view(fixture(), &controls, &BTreeSet::new());
        assert_eq!(view.count, 3);
        assert!(matches!(
            view.rows.first(),
            Some(EnrollmentRow::Header(group)) if group == "home"
        ));
        assert_eq!(view.item(0).map(|item| item.id.as_str()), Some("mail"));
        assert_eq!(
            view.item(1).map(|item| item.id.as_str()),
            Some("db"),
            "group items use the selected sort"
        );
        assert_eq!(
            view.item(2).map(|item| item.id.as_str()),
            Some("fax"),
            "group items use the selected sort"
        );
        assert_eq!(view.row_for_item(0), Some(1));
        assert_eq!(view.row_for_item(1), Some(3));
    }

    #[test]
    fn enrollment_status_sort_prioritizes_pending() {
        let controls = EnrollmentControls {
            sort: EnrollmentSort::Status,
            ..EnrollmentControls::default()
        };
        let view = build_enrollment_view(fixture(), &controls, &BTreeSet::new());
        let ids = (0..view.count)
            .filter_map(|index| view.item(index).map(|item| item.id.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(ids, ["mail", "db", "fax"]);
    }
}
