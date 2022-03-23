//! Time related utils.

use anyhow::Result;
use chrono::{SecondsFormat, Utc};

/// We will use UTC time across the whole reqsign lib.
pub type DateTime = chrono::DateTime<Utc>;

/// Create datetime of now.
pub fn now() -> DateTime {
    Utc::now()
}

/// Format time into date: `20220301`
pub fn format_date(t: DateTime) -> String {
    t.format("%Y%m%d").to_string()
}

/// Format time into ISO8601: `20220313T072004Z`
pub fn format_iso8601(t: DateTime) -> String {
    t.format("%Y%m%dT%H%M%SZ").to_string()
}

/// Format time into http date: `Sun, 06 Nov 1994 08:49:37 GMT`
///
/// ## Note
///
/// HTTP date is slightly different from RFC2822.
///
/// - Timezone is fixed to GMT.
/// - Day must be 2 digit.
pub fn format_http_date(t: DateTime) -> String {
    t.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

/// Format time into RFC2822: `Tue, 01 Jul 2003 10:52:37 +0200`
///
/// - [Reference](https://httpwg.org/specs/rfc7231.html#http.date)
pub fn format_rfc2822(t: DateTime) -> String {
    t.to_rfc2822()
}

/// Format time into RFC3339: `2022-03-13T07:20:04Z`
pub fn format_rfc3339(t: DateTime) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Parse time from RFC2822.
///
/// All of them are valid time:
///
/// - `Tue, 1 Jul 2003 10:52:37 +0200`
/// - `Tue, 01 Jul 2003 10:52:37 +0200`
/// - `Tue, 1 Jul 2003 10:52:37 GMT`
pub fn parse_rfc2822(s: &str) -> Result<DateTime> {
    Ok(chrono::DateTime::parse_from_rfc2822(s)?.with_timezone(&Utc))
}

/// Parse time from RFC3339.
///
/// All of them are valid time:
///
/// - `2022-03-13T07:20:04Z`
/// - `2022-03-01T08:12:34+00:00`
/// - `2022-03-01T08:12:34.00+00:00`
pub fn parse_rfc3339(s: &str) -> Result<DateTime> {
    Ok(chrono::DateTime::parse_from_rfc3339(s)?.with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::prelude::*;

    #[test]
    fn test_format_date() {
        let t = Utc.ymd(2022, 3, 1).and_hms(8, 12, 34);
        assert_eq!("20220301", format_date(t))
    }

    #[test]
    fn test_format_ios8601() {
        let t = Utc.ymd(2022, 3, 1).and_hms(8, 12, 34);
        assert_eq!("20220301T081234Z", format_iso8601(t))
    }

    #[test]
    fn test_format_http_date() {
        let t = Utc.ymd(2022, 3, 1).and_hms(8, 12, 34);
        assert_eq!("Tue, 01 Mar 2022 08:12:34 GMT", format_http_date(t))
    }

    #[test]
    fn test_format_rfc2822() {
        let t = Utc.ymd(2022, 3, 1).and_hms(8, 12, 34);
        assert_eq!("Tue, 01 Mar 2022 08:12:34 +0000", format_rfc2822(t))
    }

    #[test]
    fn test_format_rfc3339() {
        let t = Utc.ymd(2022, 3, 1).and_hms(8, 12, 34);
        assert_eq!("2022-03-01T08:12:34Z", format_rfc3339(t))
    }

    #[test]
    fn test_parse_rfc2822() {
        let t = Utc.ymd(2022, 3, 1).and_hms(8, 12, 34);

        for v in [
            "Tue, 01 Mar 2022 08:12:34 +0000",
            "Tue, 01 Mar 2022 08:12:34 GMT",
            "Tue, 01 Mar 2022 08:12:34 UT",
            "Tue, 1 Mar 2022 08:12:34 +0000",
        ] {
            assert_eq!(t, parse_rfc2822(v).expect("must be valid time"));
        }
    }

    #[test]
    fn test_parse_rfc3339() {
        let t = Utc.ymd(2022, 3, 1).and_hms(8, 12, 34);

        for v in [
            "2022-03-01T08:12:34Z",
            "2022-03-01T08:12:34+00:00",
            "2022-03-01T08:12:34.00+00:00",
        ] {
            assert_eq!(t, parse_rfc3339(v).expect("must be valid time"));
        }
    }
}
