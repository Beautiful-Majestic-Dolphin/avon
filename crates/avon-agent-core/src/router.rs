use std::net::IpAddr;

use avon_common::ids::SessionId;
use avon_tunnel::RouteTable;
use ipnet::IpNet;

/// LPM from destination to the hub/peer session that owns it. Thin wrapper
/// over the shared `avon_tunnel::RouteTable` so the agent and gateway use
/// identical lookup semantics.
pub struct Router {
    table: std::sync::Arc<RouteTable>,
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

impl Router {
    pub fn new() -> Self {
        Self {
            table: std::sync::Arc::new(RouteTable::new()),
        }
    }

    pub fn inner(&self) -> &RouteTable {
        &self.table
    }
}

impl Clone for Router {
    fn clone(&self) -> Self {
        Self {
            table: self.table.clone(),
        }
    }
}

impl Router {
    pub fn set_routes(&self, routes: &[IpNet], session: SessionId) {
        // Remove old routes for this session first.
        self.table.remove_session(&session);
        for net in routes {
            self.table.insert(*net, session);
        }
    }

    pub fn remove_session(&self, session: &SessionId) {
        self.table.remove_session(session);
    }

    pub fn add_route(&self, net: IpNet, session: SessionId) {
        self.table.insert(net, session);
    }

    pub fn lookup(&self, dst: IpAddr) -> Option<SessionId> {
        self.table.lookup(dst)
    }

    pub fn len(&self) -> usize {
        self.table.len()
    }

    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }
}
