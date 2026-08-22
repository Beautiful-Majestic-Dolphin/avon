use std::ops::RangeInclusive;

use chrono::Weekday;
use ipnet::IpNet;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SpecError {
    #[error("unsupported policy version {0} (expected 2)")]
    Version(u8),
    #[error("{0} selector is empty; set `any: true` to match everything")]
    EmptySelector(&'static str),
    #[error("cidrs are only allowed in the destination selector")]
    CidrInSource,
    #[error("ports are only meaningful for tcp or udp")]
    PortsWithoutL4Protocol,
    #[error("invalid port spec: {0}")]
    Port(String),
    #[error("unknown timezone {0}")]
    Timezone(String),
    #[error("invalid time {0} (expected HH:MM)")]
    Time(String),
    #[error("time window needs at least one day")]
    NoDays,
    #[error("priority must be within 0..=10000")]
    Priority,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Any,
}

/// "22,443,8000-8100"; empty means every port.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PortSet(pub Vec<RangeInclusive<u16>>);

impl PortSet {
    pub fn parse(s: &str) -> Result<Self, SpecError> {
        let mut ranges = Vec::new();
        for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            let (a, b) = match part.split_once('-') {
                Some((a, b)) => (a.trim(), b.trim()),
                None => (part, part),
            };
            let lo: u16 = a.parse().map_err(|_| SpecError::Port(part.to_string()))?;
            let hi: u16 = b.parse().map_err(|_| SpecError::Port(part.to_string()))?;
            if lo > hi {
                return Err(SpecError::Port(part.to_string()));
            }
            ranges.push(lo..=hi);
        }
        Ok(Self(ranges))
    }
    pub fn contains(&self, port: u16) -> bool {
        self.0.is_empty() || self.0.iter().any(|r| r.contains(&port))
    }
    pub fn is_all(&self) -> bool {
        self.0.is_empty()
    }
}

impl Serialize for PortSet {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let text = self
            .0
            .iter()
            .map(|r| {
                if r.start() == r.end() {
                    r.start().to_string()
                } else {
                    format!("{}-{}", r.start(), r.end())
                }
            })
            .collect::<Vec<_>>()
            .join(",");
        s.serialize_str(&text)
    }
}
impl<'de> Deserialize<'de> for PortSet {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        if s.trim().is_empty() {
            return Ok(Self(vec![]));
        }
        PortSet::parse(&s).map_err(serde::de::Error::custom)
    }
}
impl JsonSchema for PortSet {
    fn schema_name() -> String {
        "PortSet".into()
    }
    fn json_schema(_: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        serde_json::from_value(serde_json::json!({ "type": "string", "pattern": "^\\s*$|^\\d{1,5}(-\\d{1,5})?(\\s*,\\s*\\d{1,5}(-\\d{1,5})?)*$", "description": "Comma-separated ports and ranges, e.g. \"22,443,8000-8100\"; empty = all" })).unwrap_or(schemars::schema::Schema::Bool(true))
    }
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
pub struct L4Rule {
    pub protocol: Protocol,
    #[serde(default)]
    pub ports: PortSet,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, Default, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Selector {
    pub pods: Vec<Uuid>,
    pub devices: Vec<Uuid>,
    pub device_classes: Vec<Uuid>,
    #[schemars(with = "Vec<String>")]
    pub cidrs: Vec<IpNet>,
    pub any: bool,
}

impl Selector {
    pub fn is_empty(&self) -> bool {
        self.pods.is_empty()
            && self.devices.is_empty()
            && self.device_classes.is_empty()
            && self.cidrs.is_empty()
            && !self.any
    }
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AttestationRequirement {
    Any,
    Verified,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, Default, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct PostureRequirements {
    pub firewall_enabled: Option<bool>,
    pub disk_encrypted: Option<bool>,
    pub screen_lock_enabled: Option<bool>,
    pub min_os_version: Option<String>,
    pub max_hours_since_update: Option<u32>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TimeWindow {
    pub start: String,
    pub end: String,
    #[schemars(with = "Vec<String>")]
    #[serde(with = "weekdays")]
    pub days: Vec<Weekday>,
    pub timezone: String,
}

mod weekdays {
    use chrono::Weekday;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(v: &[Weekday], s: S) -> Result<S::Ok, S::Error> {
        v.iter()
            .map(|d| d.to_string().to_lowercase()[..3].to_string())
            .collect::<Vec<_>>()
            .serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Weekday>, D::Error> {
        let v: Vec<String> = Vec::deserialize(d)?;
        v.iter()
            .map(|s| match s.to_lowercase().as_str() {
                "mon" => Ok(Weekday::Mon),
                "tue" => Ok(Weekday::Tue),
                "wed" => Ok(Weekday::Wed),
                "thu" => Ok(Weekday::Thu),
                "fri" => Ok(Weekday::Fri),
                "sat" => Ok(Weekday::Sat),
                "sun" => Ok(Weekday::Sun),
                _ => Err(serde::de::Error::custom(format!("invalid weekday {s}"))),
            })
            .collect()
    }
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, Default, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Conditions {
    pub time_window: Option<TimeWindow>,
    pub posture: Option<PostureRequirements>,
    pub attestation: Option<AttestationRequirement>,
    pub max_risk_score: Option<u8>,
}

fn default_priority() -> i32 {
    100
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicySpec {
    pub version: u8,
    pub effect: Effect,
    #[serde(default = "default_priority")]
    pub priority: i32,
    pub source: Selector,
    pub destination: Selector,
    #[serde(default)]
    pub l4: Vec<L4Rule>,
    #[serde(default)]
    pub conditions: Conditions,
}

pub(crate) fn parse_hhmm(s: &str) -> Result<(u32, u32), SpecError> {
    let (h, m) = s
        .split_once(':')
        .ok_or_else(|| SpecError::Time(s.to_string()))?;
    let h: u32 = h.parse().map_err(|_| SpecError::Time(s.to_string()))?;
    let m: u32 = m.parse().map_err(|_| SpecError::Time(s.to_string()))?;
    if h > 23 || m > 59 {
        return Err(SpecError::Time(s.to_string()));
    }
    Ok((h, m))
}

impl PolicySpec {
    pub fn validate(&self) -> Result<(), SpecError> {
        if self.version != 2 {
            return Err(SpecError::Version(self.version));
        }
        if !(0..=10000).contains(&self.priority) {
            return Err(SpecError::Priority);
        }
        if self.source.is_empty() {
            return Err(SpecError::EmptySelector("source"));
        }
        if self.destination.is_empty() {
            return Err(SpecError::EmptySelector("destination"));
        }
        if !self.source.cidrs.is_empty() {
            return Err(SpecError::CidrInSource);
        }
        for rule in &self.l4 {
            if !rule.ports.is_all() && !matches!(rule.protocol, Protocol::Tcp | Protocol::Udp) {
                return Err(SpecError::PortsWithoutL4Protocol);
            }
        }
        if let Some(tw) = &self.conditions.time_window {
            if tw.days.is_empty() {
                return Err(SpecError::NoDays);
            }
            tw.timezone
                .parse::<chrono_tz::Tz>()
                .map_err(|_| SpecError::Timezone(tw.timezone.clone()))?;
            parse_hhmm(&tw.start)?;
            parse_hhmm(&tw.end)?;
        }
        Ok(())
    }
}
