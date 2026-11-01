use std::{fs, io::Write as _, os::unix::fs::PermissionsExt as _, path::PathBuf};

use ipnet::IpNet;
use ssh_key_sync_core::{Config, GroupConfig, KeyConfig, Visibility, parse_public_key, unix_now};

pub(crate) struct Editor {
    path: PathBuf,
    config: Config,
}

impl Editor {
    pub(crate) fn open(path: impl Into<PathBuf>) -> Result<Self, Box<dyn std::error::Error>> {
        let path = path.into();
        let config = Config::load(&path)?;
        Ok(Self { path, config })
    }

    pub(crate) fn add_group(
        &mut self,
        name: String,
        public: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if self.config.groups.contains_key(&name) {
            return Err(format!("group already exists: {name}").into());
        }
        self.config.groups.insert(
            name,
            GroupConfig {
                visibility: if public {
                    Visibility::Public
                } else {
                    Visibility::Private
                },
                cidrs: vec![],
            },
        );
        self.save()
    }

    pub(crate) fn remove_group(&mut self, name: &str) -> Result<(), Box<dyn std::error::Error>> {
        if name == self.config.default_group {
            return Err("cannot remove the default group".into());
        }
        if self.config.tokens.iter().any(|token| token.group == name)
            || self
                .config
                .keys
                .values()
                .any(|key| key.groups.iter().any(|group| group == name))
        {
            return Err("group is still referenced by keys or tokens".into());
        }
        if self.config.groups.remove(name).is_none() {
            return Err(format!("unknown group: {name}").into());
        }
        self.save()
    }

    pub(crate) fn add_cidr(
        &mut self,
        group: &str,
        cidr: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cidr = cidr.parse::<IpNet>()?;
        let group = self.config.groups.get_mut(group).ok_or("unknown group")?;
        if !group.cidrs.contains(&cidr) {
            group.cidrs.push(cidr);
        }
        self.save()
    }

    pub(crate) fn remove_cidr(
        &mut self,
        group: &str,
        cidr: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cidr = cidr.parse::<IpNet>()?;
        let group = self.config.groups.get_mut(group).ok_or("unknown group")?;
        group.cidrs.retain(|item| item != &cidr);
        self.save()
    }

    pub(crate) fn add_key(
        &mut self,
        owner: &str,
        group: &str,
        key: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if !self.config.groups.contains_key(group) {
            return Err(format!("unknown group: {group}").into());
        }
        let parsed = parse_public_key(key)?;
        if self
            .config
            .keys
            .values()
            .flat_map(|entry| &entry.keys)
            .filter_map(|line| parse_public_key(line).ok())
            .any(|existing| existing.fingerprint == parsed.fingerprint)
        {
            return Err("key already exists".into());
        }
        let entry = self
            .config
            .keys
            .entry(owner.to_owned())
            .or_insert_with(|| KeyConfig {
                groups: vec![],
                keys: vec![],
            });
        entry.keys.push(parsed.authorized_keys);
        if !entry.groups.iter().any(|item| item == group) {
            entry.groups.push(group.to_owned());
        }
        self.save()
    }

    pub(crate) fn remove_key(
        &mut self,
        owner: &str,
        fingerprint: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let entry = self.config.keys.get_mut(owner).ok_or("unknown key owner")?;
        entry.keys.retain(|line| {
            parse_public_key(line).map_or(true, |key| key.fingerprint != fingerprint)
        });
        if entry.keys.is_empty() {
            self.config.keys.remove(owner);
        }
        self.save()
    }

    pub(crate) fn assign_key(
        &mut self,
        owner: &str,
        group: &str,
        assigned: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if !self.config.groups.contains_key(group) {
            return Err(format!("unknown group: {group}").into());
        }
        let entry = self.config.keys.get_mut(owner).ok_or("unknown key owner")?;
        if assigned {
            if !entry.groups.iter().any(|item| item == group) {
                entry.groups.push(group.to_owned());
            }
        } else {
            entry.groups.retain(|item| item != group);
        }
        self.save()
    }

    fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let text = toml::to_string_pretty(&self.config)?;
        Config::parse(&text)?;
        let parent = self.path.parent().ok_or("configuration has no parent")?;
        let backup = self
            .path
            .with_extension(format!("before-edit-{}", unix_now()));
        if self.path.exists() {
            fs::copy(&self.path, backup)?;
        }
        let mut temp = tempfile::NamedTempFile::new_in(parent)?;
        temp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o640))?;
        temp.write_all(text.as_bytes())?;
        temp.as_file_mut().sync_all()?;
        temp.persist(&self.path)?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const CONFIG: &str = r#"
schema_version = 1
listen = "127.0.0.1:18080"
signing_key_file = "/tmp/signing.key"
default_group = "public"
[groups.public]
visibility = "public"
[keys.example]
groups = ["public"]
keys = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti test"]
"#;

    #[test]
    fn edits_are_validated_and_persisted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.toml");
        fs::write(&path, CONFIG).unwrap();
        let mut editor = Editor::open(&path).unwrap();
        editor.add_group("home".into(), false).unwrap();
        editor.add_cidr("home", "203.0.113.0/24").unwrap();
        editor.assign_key("example", "home", true).unwrap();
        let config = Config::load(&path).unwrap();
        assert!(config.groups.contains_key("home"));
        assert_eq!(
            config.keys["example"].groups,
            vec!["public".to_owned(), "home".to_owned()]
        );
    }
}
