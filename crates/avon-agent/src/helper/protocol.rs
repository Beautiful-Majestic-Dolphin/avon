use serde::{Deserialize, Serialize};

pub const MAX_LINE_BYTES: usize = 65_536;
pub const MAX_ROUTES: usize = 1_024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRules {
    pub rules: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum HelperRequest {
    CreateTun {
        name: String,
        mtu: u16,
    },
    Configure {
        v4: String,
        v6: Option<String>,
        mtu: u16,
        allowed_routes: Vec<String>,
    },
    SetRoutes {
        add: Vec<String>,
        remove: Vec<String>,
    },
    ApplyFirewall {
        rules: FirewallRules,
    },
    ClearFirewall,
    Shutdown,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "res", rename_all = "snake_case", deny_unknown_fields)]
pub enum HelperResponse {
    TunReady { name: String, mtu: u16 },
    Ok,
    Error { message: String },
}
