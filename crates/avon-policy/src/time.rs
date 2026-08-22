use chrono::{Datelike, TimeZone, Timelike, Utc, Weekday};
use chrono_tz::Tz;

use crate::spec::{parse_hhmm, SpecError, TimeWindow};

fn local(tw: &TimeWindow, now_unix: i64) -> Result<(Tz, chrono::DateTime<Tz>), SpecError> {
    let tz: Tz = tw
        .timezone
        .parse()
        .map_err(|_| SpecError::Timezone(tw.timezone.clone()))?;
    let now = Utc
        .timestamp_opt(now_unix, 0)
        .single()
        .ok_or_else(|| SpecError::Time("now".into()))?;
    Ok((tz, now.with_timezone(&tz)))
}

/// Active when the local day is listed and the local time is inside
/// [start, end] — or, for overnight windows (end < start), after start on a
/// listed day or before end on the day following a listed day.
pub fn window_active(tw: &TimeWindow, now_unix: i64) -> Result<bool, SpecError> {
    let (_, local) = local(tw, now_unix)?;
    let (sh, sm) = parse_hhmm(&tw.start)?;
    let (eh, em) = parse_hhmm(&tw.end)?;
    let start = sh * 60 + sm;
    let end = eh * 60 + em;
    let minute = local.hour() * 60 + local.minute();
    let today: Weekday = local.weekday();
    let yesterday = today.pred();
    if start <= end {
        Ok(tw.days.contains(&today) && minute >= start && minute <= end)
    } else {
        Ok((tw.days.contains(&today) && minute >= start)
            || (tw.days.contains(&yesterday) && minute <= end))
    }
}

/// Scan forward minute by minute (bounded to 8 days) for the next change.
pub fn next_window_change(tw: &TimeWindow, now_unix: i64) -> Result<i64, SpecError> {
    let current = window_active(tw, now_unix)?;
    let mut t = now_unix - now_unix % 60 + 60;
    let limit = now_unix + 8 * 86_400;
    while t <= limit {
        if window_active(tw, t)? != current {
            return Ok(t);
        }
        t += 60;
    }
    Ok(limit)
}
