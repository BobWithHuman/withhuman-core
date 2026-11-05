//! Where the viewer finds Neo4j, kept in the app's config folder between launches.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub neo4j_url: String,
    pub database: String,
    pub user: String,
    pub password: String,
    /// Reads the bundled demo graph instead of Neo4j.
    pub demo: bool,
}

impl Default for Settings {
    /// The same defaults as `server.py`, so a local `deploy/docker` stack answers out of the box.
    fn default() -> Self {
        let env = |key: &str, fallback: &str| std::env::var(key).unwrap_or_else(|_| fallback.to_owned());
        Self {
            neo4j_url: env("NEO4J_URL", "http://127.0.0.1:7474"),
            database: env("NEO4J_DATABASE", "neo4j"),
            user: env("NEO4J_USER", "neo4j"),
            password: env("NEO4J_PASSWORD", "withhuman-e2e"),
            demo: std::env::var("VIEWER_MOCK").is_ok_and(|v| v == "1"),
        }
    }
}

/// What the page sees: everything but the password itself.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Public {
    pub neo4j_url: String,
    pub database: String,
    pub user: String,
    pub has_password: bool,
    pub demo: bool,
    pub path: String,
}

/// A change from the settings form; a missing password keeps the stored one.
#[derive(Deserialize)]
pub struct Change {
    pub neo4j_url: String,
    pub database: String,
    pub user: String,
    pub password: Option<String>,
    pub demo: bool,
}

impl Settings {
    pub fn public(&self, path: &Path) -> Public {
        Public {
            neo4j_url: self.neo4j_url.clone(),
            database: self.database.clone(),
            user: self.user.clone(),
            has_password: !self.password.is_empty(),
            demo: self.demo,
            path: path.display().to_string(),
        }
    }

    pub fn apply(&self, change: Change) -> Result<Self, String> {
        let url = change.neo4j_url.trim().trim_end_matches('/').to_owned();
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            return Err("Neo4j 주소는 http:// 또는 https://로 시작해야 합니다.".into());
        }
        if change.database.trim().is_empty() || change.user.trim().is_empty() {
            return Err("데이터베이스와 사용자 이름을 채워 주세요.".into());
        }
        Ok(Self {
            neo4j_url: url,
            database: change.database.trim().to_owned(),
            user: change.user.trim().to_owned(),
            password: change.password.unwrap_or_else(|| self.password.clone()),
            demo: change.demo,
        })
    }

    /// `VIEWER_MOCK=1` opens the demo whatever was saved, without changing the file.
    pub fn load(path: &Path) -> Self {
        let mut settings: Self =
            fs::read_to_string(path).ok().and_then(|text| serde_json::from_str(&text).ok()).unwrap_or_default();
        if std::env::var("VIEWER_MOCK").is_ok_and(|v| v == "1") {
            settings.demo = true;
        }
        settings
    }

    /// Saves the settings readable by this user only, since they hold the password.
    pub fn save(&self, path: &PathBuf) -> Result<(), String> {
        if let Some(folder) = path.parent() {
            fs::create_dir_all(folder).map_err(|e| e.to_string())?;
        }
        let text = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        fs::write(path, text).map_err(|e| format!("설정을 저장하지 못했습니다: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}
