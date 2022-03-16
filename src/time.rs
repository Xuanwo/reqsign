use std::time::SystemTime;

use anyhow::Result;
use time::format_description::FormatItem;
use time::formatting::Formattable;
use time::macros::format_description;
use time::parsing::Parsable;

/// Export Format from time crate.
pub type Format = &'static [FormatItem<'static>];

/// Export PrimitiveDateTime from time crate.
#[allow(dead_code)]
pub type PrimitiveDateTime = time::PrimitiveDateTime;

/// Export OffsetDateTime from time crate.
#[allow(dead_code)]
pub type OffsetDateTime = time::OffsetDateTime;

/// Date format: "20220313"
pub const DATE: Format = format_description!("[year][month][day]");

/// Time format for ISO 8601: "20220313T072004Z"
pub const ISO8601: Format = format_description!("[year][month][day]T[hour][minute][second]Z");

/// Time format for ISO 8601: "2022-03-13T07:20:04Z"
pub const ISO8601_WITH_SEPERATOR: Format =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");

/// Time format for RFC 2822: "Fri, 21 Nov 1997 09:55:06 -0600"
#[allow(dead_code)]
pub type RFC2822 = time::format_description::well_known::Rfc2822;

/// Time format for RFC 3339: "1985-04-12T23:20:50.52Z"
#[allow(dead_code)]
pub type RFC3339 = time::format_description::well_known::Rfc3339;

/// Format input system time into string.
pub fn format(time: SystemTime, format: impl Formattable) -> String {
    let time = OffsetDateTime::from(time);
    time.format(&format).expect("input time must be valid")
}

/// Parse input string into system time.
pub fn parse(s: &str, format: impl Parsable) -> Result<SystemTime> {
    let time = PrimitiveDateTime::parse(s, &format)?.assume_utc();
    Ok(time.into())
}
