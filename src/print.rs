//! Human-friendly print helpers shared across dracon-warden commands.
//!
//! Goal: keep CLI output consistent across the binary without pulling in a
//! colour/formatting dependency. Everything is stdlib + `comfy-table` (which
//! is already a dependency for the table-style commands).
//!
//! NO_COLOR spec: <https://no-color.org/> — if the env var is set (to anything,
//! including empty), colour MUST be disabled.

// Allow dead code on this module: the helpers below are part of the binary's
// public API surface for shared output formatting. Callers are added
// incrementally as commands adopt the standardised formatting; the helpers
// are intentionally `pub` so future commands can use them without re-export.
#![allow(dead_code)]

/// Format a byte count as a human-readable string (binary units, 2 decimals max).
pub fn format_bytes(n: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut value = n as f64;
    let mut unit_idx = 0;
    while value >= 1024.0 && unit_idx < UNITS.len() - 1 {
        value /= 1024.0;
        unit_idx += 1;
    }
    if unit_idx == 0 {
        format!("{} {}", n, UNITS[0])
    } else if value >= 100.0 {
        format!("{:.0} {}", value, UNITS[unit_idx])
    } else if value >= 10.0 {
        format!("{:.1} {}", value, UNITS[unit_idx])
    } else {
        format!("{:.2} {}", value, UNITS[unit_idx])
    }
}

/// Format a duration in seconds as a compact human-readable string.
/// Negative or zero values render as "0s".
pub fn format_secs(secs: u64) -> String {
    if secs < 60 {
        return format!("{}s", secs);
    }
    if secs < 3600 {
        let m = secs / 60;
        let s = secs % 60;
        if s == 0 {
            return format!("{}m", m);
        }
        return format!("{}m {}s", m, s);
    }
    if secs < 86_400 {
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        if m == 0 {
            return format!("{}h", h);
        }
        return format!("{}h {}m", h, m);
    }
    let d = secs / 86_400;
    let h = (secs % 86_400) / 3600;
    if h == 0 {
        return format!("{}d", d);
    }
    format!("{}d {}h", d, h)
}

/// Should ANSI colour codes be emitted? Honours the `NO_COLOR` env var and tty detection.
pub fn should_color() -> bool {
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    if std::env::var_os("DRACON_FORCE_COLOR").is_some() {
        return true;
    }
    use std::io::IsTerminal;
    std::io::stdout().is_terminal()
}

/// Render a boolean as a compact on/off string for tables and flags rows.
pub fn onoff(b: bool) -> &'static str {
    if b {
        "on"
    } else {
        "off"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_bytes_mib() {
        assert_eq!(format_bytes(52_428_800), "50.0 MiB");
        assert_eq!(format_bytes(1_572_864), "1.50 MiB");
    }

    #[test]
    fn format_secs_units() {
        assert_eq!(format_secs(0), "0s");
        assert_eq!(format_secs(60), "1m");
        assert_eq!(format_secs(3600), "1h");
    }
}
