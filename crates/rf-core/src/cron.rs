//! Standard 5-field cron (minute hour dom month dow), UTC, evaluated
//! on minute boundaries. Supports `*`, lists, ranges, and `/step`.
//! Vixie-cron dom/dow OR semantics: when both are restricted, a match
//! on either fires.
//!
//! No chrono: civil-date math is Howard Hinnant's days-from-epoch
//! algorithm, a page of integer arithmetic.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CronExpr {
    minute: u64, // bitmask 0..=59
    hour: u32,   // bitmask 0..=23
    dom: u32,    // bitmask 1..=31
    month: u16,  // bitmask 1..=12
    dow: u8,     // bitmask 0..=6 (0 = Sunday)
    dom_star: bool,
    dow_star: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CronParseError(pub String);

impl std::fmt::Display for CronParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "cron parse error: {}", self.0)
    }
}

impl std::error::Error for CronParseError {}

fn parse_field(field: &str, min: u32, max: u32) -> Result<(u64, bool), CronParseError> {
    let mut mask: u64 = 0;
    let is_star = field == "*" || field.starts_with("*/") && !field.contains(',');
    for part in field.split(',') {
        let (range, step) = match part.split_once('/') {
            Some((r, s)) => {
                let step: u32 = s
                    .parse()
                    .map_err(|_| CronParseError(format!("bad step in {part:?}")))?;
                if step == 0 {
                    return Err(CronParseError(format!("zero step in {part:?}")));
                }
                (r, step)
            }
            None => (part, 1),
        };
        let (lo, hi) = if range == "*" {
            (min, max)
        } else if let Some((a, b)) = range.split_once('-') {
            let lo = a
                .parse()
                .map_err(|_| CronParseError(format!("bad range in {part:?}")))?;
            let hi = b
                .parse()
                .map_err(|_| CronParseError(format!("bad range in {part:?}")))?;
            (lo, hi)
        } else {
            let v: u32 = range
                .parse()
                .map_err(|_| CronParseError(format!("bad value {range:?}")))?;
            (v, v)
        };
        if lo < min || hi > max || lo > hi {
            return Err(CronParseError(format!("{part:?} out of range {min}-{max}")));
        }
        let mut v = lo;
        while v <= hi {
            mask |= 1u64 << v;
            v += step;
        }
    }
    if mask == 0 {
        return Err(CronParseError(format!("empty field {field:?}")));
    }
    Ok((mask, is_star))
}

/// (year, month 1-12, day 1-31, weekday 0=Sun) from days since epoch.
fn civil(days: i64) -> (i64, u32, u32, u32) {
    let dow = (days.rem_euclid(7) + 4) % 7; // 1970-01-01 was Thursday (4)
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32, d as u32, dow as u32)
}

impl CronExpr {
    pub fn parse(s: &str) -> Result<Self, CronParseError> {
        let fields: Vec<&str> = s.split_whitespace().collect();
        if fields.len() != 5 {
            return Err(CronParseError(format!(
                "expected 5 fields, got {} in {s:?}",
                fields.len()
            )));
        }
        let (minute, _) = parse_field(fields[0], 0, 59)?;
        let (hour, _) = parse_field(fields[1], 0, 23)?;
        let (dom, dom_star) = parse_field(fields[2], 1, 31)?;
        let (month, _) = parse_field(fields[3], 1, 12)?;
        // Accept 7 as Sunday alias.
        let dow_src = fields[4].replace('7', "0");
        let (dow, dow_star) = parse_field(&dow_src, 0, 6)?;
        Ok(CronExpr {
            minute,
            hour: hour as u32,
            dom: dom as u32,
            month: month as u16,
            dow: dow as u8,
            dom_star,
            dow_star,
        })
    }

    /// Does this expression fire at the minute containing `epoch_secs`
    /// (UTC)?
    pub fn matches(&self, epoch_secs: u64) -> bool {
        let minutes = epoch_secs / 60;
        let minute = (minutes % 60) as u32;
        let hour = ((minutes / 60) % 24) as u32;
        let days = (minutes / 60 / 24) as i64;
        let (_y, month, day, dow) = civil(days);
        if self.minute & (1 << minute) == 0 {
            return false;
        }
        if self.hour & (1 << hour) == 0 {
            return false;
        }
        if self.month & (1 << month) == 0 {
            return false;
        }
        let dom_hit = self.dom & (1 << day) != 0;
        let dow_hit = self.dow & (1 << dow) != 0;
        match (self.dom_star, self.dow_star) {
            (true, true) => true,
            (false, true) => dom_hit,
            (true, false) => dow_hit,
            // Vixie OR: both restricted → either matches.
            (false, false) => dom_hit || dow_hit,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 2026-07-31 is a Friday. 00:00 UTC epoch:
    const FRI_2026_07_31: u64 = 1_785_456_000;

    #[test]
    fn civil_is_correct_on_known_date() {
        let (y, m, d, dow) = civil((FRI_2026_07_31 / 86_400) as i64);
        assert_eq!((y, m, d), (2026, 7, 31));
        assert_eq!(dow, 5); // Friday
    }

    #[test]
    fn every_minute() {
        let c = CronExpr::parse("* * * * *").unwrap();
        assert!(c.matches(FRI_2026_07_31));
        assert!(c.matches(FRI_2026_07_31 + 60));
    }

    #[test]
    fn specific_time() {
        let c = CronExpr::parse("30 14 * * *").unwrap();
        assert!(c.matches(FRI_2026_07_31 + 14 * 3600 + 30 * 60));
        assert!(!c.matches(FRI_2026_07_31 + 14 * 3600 + 29 * 60));
    }

    #[test]
    fn steps_and_ranges() {
        let c = CronExpr::parse("*/15 9-17 * * *").unwrap();
        assert!(c.matches(FRI_2026_07_31 + 9 * 3600));
        assert!(c.matches(FRI_2026_07_31 + 17 * 3600 + 45 * 60));
        assert!(!c.matches(FRI_2026_07_31 + 8 * 3600));
        assert!(!c.matches(FRI_2026_07_31 + 9 * 3600 + 10 * 60));
    }

    #[test]
    fn dow_matching() {
        let fri_only = CronExpr::parse("0 0 * * 5").unwrap();
        assert!(fri_only.matches(FRI_2026_07_31));
        assert!(!fri_only.matches(FRI_2026_07_31 + 86_400)); // Saturday
        let sunday_as_7 = CronExpr::parse("0 0 * * 7").unwrap();
        assert!(sunday_as_7.matches(FRI_2026_07_31 + 2 * 86_400));
    }

    #[test]
    fn vixie_dom_dow_or_semantics() {
        // "day 1 OR friday"
        let c = CronExpr::parse("0 0 1 * 5").unwrap();
        assert!(c.matches(FRI_2026_07_31)); // friday, not the 1st
        assert!(c.matches(FRI_2026_07_31 + 86_400)); // Aug 1st, saturday
        assert!(!c.matches(FRI_2026_07_31 + 2 * 86_400)); // Aug 2nd, sunday
    }

    #[test]
    fn rejects_garbage() {
        for bad in [
            "",
            "* * * *",
            "60 * * * *",
            "* 24 * * *",
            "*/0 * * * *",
            "a * * * *",
        ] {
            assert!(CronExpr::parse(bad).is_err(), "{bad:?} should fail");
        }
    }
}
