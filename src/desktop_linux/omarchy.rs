use serde::Serialize;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

const COLORS: [(&str, &str); 14] = [
    ("background", "background"),
    ("dark_background", "dark-background"),
    ("lighter_background", "lighter-background"),
    ("foreground", "foreground"),
    ("dark_foreground", "dark-foreground"),
    ("bright_foreground", "bright-foreground"),
    ("accent", "accent"),
    ("selection", "selection"),
    ("muted", "muted"),
    ("red", "red"),
    ("yellow", "yellow"),
    ("orange", "orange"),
    ("green", "green"),
    ("blue", "blue"),
];
const KEYS: [&str; 19] = [
    "background",
    "dark-background",
    "lighter-background",
    "foreground",
    "dark-foreground",
    "bright-foreground",
    "accent",
    "selection",
    "muted",
    "red",
    "yellow",
    "orange",
    "green",
    "blue",
    "popup-background",
    "popup-text",
    "popup-border",
    "border-width",
    "radius",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(super) struct Theme {
    mode: String,
    vars: BTreeMap<String, String>,
}

pub(super) fn detect(env_path: Option<&Path>, default: &Path) -> bool {
    env_path
        .filter(|p| !p.as_os_str().is_empty())
        .is_some_and(|p| p.join("shell/shell.qml").is_file())
        || default.join("shell/shell.qml").is_file()
}

#[derive(Clone)]
pub(super) struct Paths {
    colors: PathBuf,
    shell: PathBuf,
    user: PathBuf,
}
impl Paths {
    pub(super) fn new(home: &Path) -> Self {
        let dir = home.join(".local/state/omarchy/current/theme");
        Self {
            colors: dir.join("colors.toml"),
            shell: dir.join("shell.toml"),
            user: home.join(".config/omarchy/shell.toml"),
        }
    }
}

type Fingerprint = Vec<Option<(PathBuf, SystemTime, u64)>>;
fn fingerprint(paths: &Paths) -> Result<Fingerprint, String> {
    [&paths.colors, &paths.shell, &paths.user]
        .into_iter()
        .enumerate()
        .map(|(i, p)| match fs::metadata(p) {
            Ok(m) => Ok(Some((
                fs::canonicalize(p).map_err(|e| e.to_string())?,
                m.modified().map_err(|e| e.to_string())?,
                m.len(),
            ))),
            Err(e) if i == 2 && e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.to_string()),
        })
        .collect()
}
fn read_toml(path: &Path) -> Result<toml::Value, String> {
    fs::read_to_string(path)
        .map_err(|e| e.to_string())?
        .parse::<toml::Value>()
        .map_err(|e| e.to_string())
}
fn merge(base: &mut toml::Value, override_value: toml::Value) {
    if let (Some(base), Some(over)) = (base.as_table_mut(), override_value.as_table()) {
        for (key, value) in over {
            if let Some(existing) = base.get_mut(key) {
                if existing.is_table() && value.is_table() {
                    merge(existing, value.clone());
                } else {
                    *existing = value.clone();
                }
            } else {
                base.insert(key.clone(), value.clone());
            }
        }
    }
}
fn color(value: &str) -> Option<String> {
    let s = value.trim();
    if let Some(hex) = s.strip_prefix('#')
        && hex.len() == 6
        && hex.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Some(format!("#{hex}").to_lowercase());
    }
    if let Some(inner) = s.strip_prefix("rgba(").and_then(|s| s.strip_suffix(')')) {
        if inner.len() == 8 && inner.bytes().all(|b| b.is_ascii_hexdigit()) {
            let r = u8::from_str_radix(&inner[0..2], 16).ok()?;
            let g = u8::from_str_radix(&inner[2..4], 16).ok()?;
            let b = u8::from_str_radix(&inner[4..6], 16).ok()?;
            let a = f64::from(u8::from_str_radix(&inner[6..8], 16).ok()?) / 255.0;
            return Some(format!("rgba({r}, {g}, {b}, {a})"));
        }
        let parts: Vec<_> = inner.split(',').map(str::trim).collect();
        if parts.len() == 4 {
            let r = parts[0].parse::<u8>().ok()?;
            let g = parts[1].parse::<u8>().ok()?;
            let b = parts[2].parse::<u8>().ok()?;
            let a = parts[3].parse::<f64>().ok()?;
            if (0.0..=1.0).contains(&a) {
                return Some(format!("rgba({r}, {g}, {b}, {a})"));
            }
        }
    }
    None
}
fn first_color(value: &str) -> Option<String> {
    let s = value.trim();
    if s.starts_with("rgba(") {
        let end = s.find(')')?;
        return color(&s[..=end]);
    }
    color(s.split_whitespace().next()?)
}
fn resolved_color(shell: &toml::Value, value: &str) -> Option<String> {
    let mut current = value;
    let mut seen = Vec::new();
    for _ in 0..16 {
        if let Some(c) = first_color(current) {
            return Some(c);
        }
        let (section, key) = current.split_once('.')?;
        if seen.contains(&current) {
            return None;
        }
        seen.push(current);
        current = shell.get(section)?.get(key)?.as_str()?;
    }
    None
}
fn rgba_with_alpha(value: &str, alpha: f64) -> Option<String> {
    if !(0.0..=1.0).contains(&alpha) {
        return None;
    }
    let c = color(value)?;
    if let Some(hex) = c.strip_prefix('#') {
        return Some(format!(
            "rgba({}, {}, {}, {})",
            u8::from_str_radix(&hex[0..2], 16).ok()?,
            u8::from_str_radix(&hex[2..4], 16).ok()?,
            u8::from_str_radix(&hex[4..6], 16).ok()?,
            alpha
        ));
    }
    let inner = c.strip_prefix("rgba(")?.strip_suffix(')')?;
    let parts: Vec<_> = inner.split(',').collect();
    Some(format!(
        "rgba({}, {}, {}, {})",
        parts[0].trim(),
        parts[1].trim(),
        parts[2].trim(),
        alpha
    ))
}
fn number(v: &toml::Value) -> Option<f64> {
    v.as_float().or_else(|| v.as_integer().map(|n| n as f64))
}
pub(super) fn resolve(colors: &toml::Value, shell: &toml::Value, radius: u32) -> Theme {
    let mut vars = BTreeMap::new();
    for (key, name) in COLORS {
        if let Some(value) = colors
            .get(key)
            .and_then(toml::Value::as_str)
            .and_then(color)
        {
            vars.insert(format!("--omarchy-{name}"), value);
        }
    }
    if let Some(pop) = shell.get("popups") {
        let alpha = pop.get("background-alpha").map_or(Some(1.0), number);
        if let Some(v) = pop
            .get("background")
            .and_then(toml::Value::as_str)
            .and_then(|v| resolved_color(shell, v))
            .and_then(|v| rgba_with_alpha(&v, alpha?))
        {
            vars.insert("--omarchy-popup-background".into(), v);
        }
        for (key, name) in [("text", "popup-text"), ("border", "popup-border")] {
            if let Some(v) = pop
                .get(key)
                .and_then(toml::Value::as_str)
                .and_then(|v| resolved_color(shell, v))
            {
                vars.insert(format!("--omarchy-{name}"), v);
            }
        }
    }
    let width = shell
        .get("popups")
        .and_then(|p| p.get("border-width"))
        .and_then(|v| {
            number(v)
                .or_else(|| v.as_array().and_then(|a| a.first()).and_then(number))
                .or_else(|| {
                    v.as_str()
                        .and_then(|s| s.split_whitespace().next())
                        .and_then(|s| s.parse().ok())
                })
        })
        .filter(|n| n.is_finite() && *n >= 0.0)
        .unwrap_or(2.0);
    vars.insert("--omarchy-border-width".into(), format!("{width}px"));
    vars.insert("--omarchy-radius".into(), format!("{radius}px"));
    Theme {
        mode: if colors.get("mode").and_then(toml::Value::as_str) == Some("light") {
            "light"
        } else {
            "dark"
        }
        .into(),
        vars,
    }
}
pub(super) fn script(theme: &Theme) -> String {
    let keys: Vec<_> = KEYS.iter().map(|key| format!("--omarchy-{key}")).collect();
    let json = serde_json::to_string(theme).expect("theme JSON");
    let keys = serde_json::to_string(&keys).expect("keys JSON");
    format!(
        "((t)=>{{const e=document.documentElement;e.dataset.desktop='omarchy';e.dataset.omarchyMode=t.mode;for(const k of {keys}){{if(Object.hasOwn(t.vars,k))e.style.setProperty(k,t.vars[k]);else e.style.removeProperty(k);}}}})({json});"
    )
}
fn load(paths: &Paths, rounding: impl FnOnce() -> u32) -> Result<(Fingerprint, Theme), String> {
    let before = fingerprint(paths)?;
    let colors = read_toml(&paths.colors)?;
    let mut shell = read_toml(&paths.shell)?;
    if before[2].is_some() {
        merge(&mut shell, read_toml(&paths.user)?);
    }
    let theme = resolve(&colors, &shell, rounding());
    if before != fingerprint(paths)? {
        return Err("theme changed during read".into());
    }
    Ok((before, theme))
}
fn update(
    paths: &Paths,
    previous: &mut Option<(Fingerprint, Theme)>,
    rounding: impl FnOnce() -> u32,
) -> Option<Theme> {
    let current = fingerprint(paths).ok()?;
    if previous.as_ref().is_some_and(|(old, _)| *old == current) {
        return None;
    }
    let (fp, theme) = load(paths, rounding).ok()?;
    let different = previous.as_ref().is_none_or(|(_, old)| *old != theme);
    *previous = Some((fp, theme.clone()));
    different.then_some(theme)
}

pub(super) fn start(paths: Paths, reply: impl Fn(Theme) + Send + 'static) -> Result<Theme, String> {
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("vpnt-desktop-theme".into())
        .spawn(move || {
            let first = load(&paths, super::placement::rounding);
            let mut previous = first.as_ref().ok().cloned();
            let initial = first.map(|(_, theme)| theme).unwrap_or_else(|_| {
                resolve(
                    &toml::Value::Table(Default::default()),
                    &toml::Value::Table(Default::default()),
                    0,
                )
            });
            if tx.send(initial).is_err() {
                return;
            }
            loop {
                std::thread::sleep(Duration::from_secs(1));
                if let Some(theme) = update(&paths, &mut previous, super::placement::rounding) {
                    reply(theme);
                }
            }
        })
        .map_err(|e| e.to_string())?;
    rx.recv().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "vpnt-theme-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn fixture() -> (Temp, Paths) {
        let t = Temp::new();
        let p = Paths::new(&t.0);
        fs::create_dir_all(p.colors.parent().unwrap()).unwrap();
        fs::create_dir_all(p.user.parent().unwrap()).unwrap();
        fs::write(
            &p.colors,
            "mode='light'\nbackground='#1a1b26'\naccent='#ABCDEF'\n",
        )
        .unwrap();
        fs::write(&p.shell,"[popups]\nbackground='#1a1b26'\nbackground-alpha=0.9\ntext='#a9b1d6'\nborder='hyprland.active-border'\n[hyprland]\nactive-border='rgba(7aa2f7ff) rgba(112233ff) 45deg'\n").unwrap();
        (t, p)
    }
    #[test]
    fn detection_tries_override_then_default() {
        let t = Temp::new();
        let custom = t.0.join("custom");
        let default = t.0.join("default");
        assert!(!detect(Some(&custom), &default));
        fs::create_dir_all(default.join("shell")).unwrap();
        fs::write(default.join("shell/shell.qml"), "").unwrap();
        assert!(detect(Some(&custom), &default));
        fs::create_dir_all(custom.join("shell")).unwrap();
        fs::write(custom.join("shell/shell.qml"), "").unwrap();
        assert!(detect(Some(&custom), &t.0.join("missing")));
        assert!(!detect(None, &t.0.join("missing")));
    }
    #[test]
    fn resolves_colors_overrides_and_rejects_hostile_values() {
        let (_t, p) = fixture();
        fs::write(&p.user, "[popups]\ntext='#010203'\nborder-width=[3,4]\n").unwrap();
        let (_, t) = load(&p, || 7).unwrap();
        assert_eq!(t.mode, "light");
        assert_eq!(t.vars["--omarchy-background"], "#1a1b26");
        assert_eq!(t.vars["--omarchy-accent"], "#abcdef");
        assert_eq!(
            t.vars["--omarchy-popup-background"],
            "rgba(26, 27, 38, 0.9)"
        );
        assert_eq!(t.vars["--omarchy-popup-text"], "#010203");
        assert_eq!(t.vars["--omarchy-popup-border"], "rgba(122, 162, 247, 1)");
        assert_eq!(t.vars["--omarchy-border-width"], "3px");
        assert_eq!(t.vars["--omarchy-radius"], "7px");
        for bad in ["red; x", "#12", "url(x)", "#fff\");alert(1)//"] {
            let mut colors = toml::map::Map::new();
            colors.insert("red".into(), toml::Value::String(bad.into()));
            let theme = resolve(
                &toml::Value::Table(colors),
                &toml::Value::Table(Default::default()),
                0,
            );
            assert!(!theme.vars.contains_key("--omarchy-red"));
            assert!(!script(&theme).contains("alert"));
        }
        assert!(
            t.vars
                .keys()
                .all(|key| KEYS.iter().any(|k| key == &format!("--omarchy-{k}")))
        );
        let js = script(&t);
        assert!(js.contains("removeProperty"));
        assert!(js.contains("setProperty"));
    }
    #[test]
    fn watcher_ignores_equal_and_invalid_updates_then_emits_change() {
        let (_t, p) = fixture();
        let (fp, t) = load(&p, || 0).unwrap();
        let mut prev = Some((fp, t.clone()));
        fs::write(
            &p.colors,
            "mode='light'\nbackground='#1a1b26'\naccent='#ABCDEF'\n# unchanged\n",
        )
        .unwrap();
        assert_eq!(update(&p, &mut prev, || 0), None);
        fs::write(&p.colors, "mode = [broken").unwrap();
        assert_eq!(update(&p, &mut prev, || 0), None);
        assert_eq!(prev.as_ref().unwrap().1, t);
        fs::write(
            &p.colors,
            "mode='dark'\nbackground='#1a1b26'\naccent='#ABCDEF'\n",
        )
        .unwrap();
        assert_eq!(update(&p, &mut prev, || 0).unwrap().mode, "dark");
    }
}
