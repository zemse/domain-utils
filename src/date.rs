//! Minimal date math for the expiry filter — no external date crate.
//!
//! Works in "days since the Unix epoch" using Howard Hinnant's well-known
//! `days_from_civil` algorithm, which is exact for the proleptic Gregorian
//! calendar. Only what `whois --expiring-within` needs: parse a `YYYY-MM-DD`
//! date, parse a duration like `30d`, and diff against today.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, bail};

/// Today's date as days since the Unix epoch (UTC).
pub fn today() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| (d.as_secs() / 86_400) as i64)
        .unwrap_or(0)
}

/// Days from now until `date` (negative if it's already past). `None` if the
/// leading `YYYY-MM-DD` of the string can't be parsed.
pub fn days_until(date: &str) -> Option<i64> {
    Some(parse_ymd(date)? - today())
}

/// Parse the leading `YYYY-MM-DD` of a date/datetime string into days-from-epoch.
/// Tolerates a trailing time component (`2025-03-04T00:00:00Z`).
fn parse_ymd(s: &str) -> Option<i64> {
    let date = s.trim().split(['T', ' ']).next()?;
    let mut parts = date.split('-');
    let y: i64 = parts.next()?.parse().ok()?;
    let m: i64 = parts.next()?.parse().ok()?;
    let d: i64 = parts.next()?.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    Some(days_from_civil(y, m, d))
}

/// Parse a duration into a number of days: a bare integer is days; suffixes
/// `d`/`w`/`m`/`y` mean days/weeks/months(=30d)/years(=365d).
pub fn parse_duration_days(s: &str) -> Result<i64> {
    let s = s.trim().to_ascii_lowercase();
    if s.is_empty() {
        bail!("empty duration");
    }
    let (num, mult) = match s.as_bytes().last() {
        Some(b'd') => (&s[..s.len() - 1], 1),
        Some(b'w') => (&s[..s.len() - 1], 7),
        Some(b'm') => (&s[..s.len() - 1], 30),
        Some(b'y') => (&s[..s.len() - 1], 365),
        Some(c) if c.is_ascii_digit() => (s.as_str(), 1),
        _ => bail!("invalid duration `{s}` (use e.g. 30, 30d, 6w, 3m, 1y)"),
    };
    let n: i64 = num
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid duration `{s}` (use e.g. 30, 30d, 6w, 3m, 1y)"))?;
    if n < 0 {
        bail!("duration must not be negative");
    }
    Ok(n * mult)
}

/// Days from the Unix epoch (1970-01-01) for a civil date. Hinnant's algorithm.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_is_day_zero() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
    }

    #[test]
    fn known_dates() {
        // 2000-01-01 is 10957 days after the epoch.
        assert_eq!(days_from_civil(2000, 1, 1), 10_957);
        assert_eq!(days_from_civil(2021, 1, 1), 18_628);
    }

    #[test]
    fn parses_ymd_and_datetime() {
        assert_eq!(parse_ymd("1970-01-01"), Some(0));
        assert_eq!(parse_ymd("2000-01-01T12:34:56Z"), Some(10_957));
        assert_eq!(parse_ymd("not a date"), None);
        assert_eq!(parse_ymd("2000-13-01"), None);
    }

    #[test]
    fn parses_durations() {
        assert_eq!(parse_duration_days("30").unwrap(), 30);
        assert_eq!(parse_duration_days("30d").unwrap(), 30);
        assert_eq!(parse_duration_days("2w").unwrap(), 14);
        assert_eq!(parse_duration_days("3m").unwrap(), 90);
        assert_eq!(parse_duration_days("1y").unwrap(), 365);
        assert!(parse_duration_days("abc").is_err());
    }
}
