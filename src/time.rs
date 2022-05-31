//! Time related utils.

use anyhow::Result;
use time::format_description::well_known::{Rfc2822, Rfc3339};
use time::format_description::FormatItem;
use time::macros::format_description;
use time::OffsetDateTime;

/// DateTime is an alias of [`time::OffsetDateTime`]
///
/// We will use UTC time across the whole reqsign lib.
pub type DateTime = OffsetDateTime;
/// Duration is an alias of [`time::Duration`]
pub type Duration = time::Duration;

/// Create datetime of now.
pub fn now() -> DateTime {
    OffsetDateTime::now_utc()
}

/// DATE is a time format like `20220301`
pub const DATE: &[FormatItem<'static>] = format_description!("[year][month][day]");

/// Format time into date: `20220301`
pub fn format_date(t: DateTime) -> String {
    t.format(DATE).expect("time must be valid")
}

/// ISO8601 is a time format like `20220313T072004Z`.
pub const ISO8601: &[FormatItem<'static>] =
    format_description!("[year][month][day]T[hour][minute][second]Z");

/// Format time into ISO8601: `20220313T072004Z`
pub fn format_iso8601(t: DateTime) -> String {
    t.format(ISO8601).expect("time must be valid")
}

/// HTTP_DATE is a time format like `Sun, 06 Nov 1994 08:49:37 GMT`.
pub const HTTP_DATE: &[FormatItem<'static>] = format_description!(
    "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT"
);

/// Format time into http date: `Sun, 06 Nov 1994 08:49:37 GMT`
///
/// ## Note
///
/// HTTP date is slightly different from RFC2822.
///
/// - Timezone is fixed to GMT.
/// - Day must be 2 digit.
pub fn format_http_date(t: DateTime) -> String {
    t.format(HTTP_DATE).expect("time must be valid")
}

/// Format time into RFC2822: `Tue, 01 Jul 2003 10:52:37 +0200`
///
/// - [Reference](https://httpwg.org/specs/rfc7231.html#http.date)
pub fn format_rfc2822(t: DateTime) -> String {
    t.format(&Rfc2822).expect("time must be valid")
}

/// Format time into RFC3339: `2022-03-13T07:20:04Z`
pub fn format_rfc3339(t: DateTime) -> String {
    t.format(&Rfc3339).expect("time must be valid")
}

/// Parse time from RFC2822.
///
/// All of them are valid time:
///
/// - `Tue, 1 Jul 2003 10:52:37 +0200`
/// - `Tue, 01 Jul 2003 10:52:37 +0200`
/// - `Tue, 1 Jul 2003 10:52:37 GMT`
pub fn parse_rfc2822(s: &str) -> Result<DateTime> {
    Ok(OffsetDateTime::parse(s, &Rfc2822)?)
}

/// Parse time from RFC3339.
///
/// All of them are valid time:
///
/// - `2022-03-13T07:20:04Z`
/// - `2022-03-01T08:12:34+00:00`
/// - `2022-03-01T08:12:34.00+00:00`
pub fn parse_rfc3339(s: &str) -> Result<DateTime> {
    Ok(OffsetDateTime::parse(s, &Rfc3339)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::PrimitiveDateTime;
    use time::{Date, Month, Time};

    fn test_time() -> OffsetDateTime {
        let date = Date::from_calendar_date(2022, Month::March, 1).expect("must be valid date");
        let time = Time::from_hms(8, 12, 34).expect("must be valid time");
        PrimitiveDateTime::new(date, time).assume_utc()
    }

    #[test]
    fn test_format_date() {
        let t = test_time();
        assert_eq!("20220301", format_date(t))
    }

    #[test]
    fn test_format_ios8601() {
        let t = test_time();
        assert_eq!("20220301T081234Z", format_iso8601(t))
    }

    #[test]
    fn test_format_http_date() {
        let t = test_time();
        assert_eq!("Tue, 01 Mar 2022 08:12:34 GMT", format_http_date(t))
    }

    #[test]
    fn test_format_rfc2822() {
        let t = test_time();
        assert_eq!("Tue, 01 Mar 2022 08:12:34 +0000", format_rfc2822(t))
    }

    #[test]
    fn test_format_rfc3339() {
        let t = test_time();
        assert_eq!("2022-03-01T08:12:34Z", format_rfc3339(t))
    }

    #[test]
    fn test_parse_rfc2822() {
        let t = test_time();

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
        let t = test_time();

        for v in [
            "2022-03-01T08:12:34Z",
            "2022-03-01T08:12:34+00:00",
            "2022-03-01T08:12:34.00+00:00",
        ] {
            assert_eq!(t, parse_rfc3339(v).expect("must be valid time"));
        }
    }
}
