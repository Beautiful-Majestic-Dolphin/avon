//! Longest-prefix-match routing table shared by gateway and agent.
//! One table serves both families; `IpNetworkTable` keys them separately.

use std::net::IpAddr;

use avon_common::ids::SessionId;
use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;
use ipnet::IpNet;
use parking_lot::RwLock;

pub struct RouteTable {
    table: RwLock<IpNetworkTable<SessionId>>,
}

impl Default for RouteTable {
    fn default() -> Self {
        Self {
            table: RwLock::new(IpNetworkTable::new()),
        }
    }
}

fn to_ipn(net: IpNet) -> Option<IpNetwork> {
    IpNetwork::new(net.network(), net.prefix_len()).ok()
}

impl RouteTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, net: IpNet, session: SessionId) {
        if let Some(n) = to_ipn(net) {
            self.table.write().insert(n, session);
        }
    }

    pub fn remove(&self, net: IpNet) {
        if let Some(n) = to_ipn(net) {
            self.table.write().remove(n);
        }
    }

    pub fn remove_session(&self, session: &SessionId) {
        let mut t = self.table.write();
        let victims: Vec<IpNetwork> = t
            .iter()
            .filter(|(_, s)| *s == session)
            .map(|(n, _)| n)
            .collect();
        for n in victims {
            t.remove(n);
        }
    }

    pub fn lookup(&self, dst: IpAddr) -> Option<SessionId> {
        self.table.read().longest_match(dst).map(|(_, s)| *s)
    }

    pub fn len(&self) -> usize {
        let t = self.table.read();
        let (v4, v6) = t.len();
        v4 + v6
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
