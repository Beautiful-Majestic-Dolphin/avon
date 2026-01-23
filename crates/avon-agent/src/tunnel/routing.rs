//! Routing table for directing packets to tunnels.
//!
//! Maps destination IP addresses to tunnel session IDs for packet routing.

use std::net::IpAddr;

use dashmap::DashMap;

use super::SessionId;

/// Routing table for tunnel packet routing.
///
/// Maps destination IP addresses to session IDs, allowing the packet
/// loop to determine which tunnel should handle outbound packets.
pub struct RoutingTable {
    routes: DashMap<IpAddr, SessionId>,
    reverse: DashMap<SessionId, Vec<IpAddr>>,
}

impl RoutingTable {
    /// Creates a new empty routing table.
    pub fn new() -> Self {
        Self {
            routes: DashMap::new(),
            reverse: DashMap::new(),
        }
    }

    /// Adds a route for a destination IP to a tunnel.
    ///
    /// # Arguments
    ///
    /// * `destination` - The destination IP address
    /// * `session_id` - The session ID of the tunnel to route to
    pub fn add_route(&self, destination: IpAddr, session_id: SessionId) {
        // Add forward mapping
        self.routes.insert(destination, session_id);

        // Add reverse mapping for cleanup
        self.reverse
            .entry(session_id)
            .or_insert_with(Vec::new)
            .push(destination);

        tracing::debug!(%destination, session_id = %hex::encode(session_id), "Added route");
    }

    /// Removes a route for a destination IP.
    ///
    /// # Arguments
    ///
    /// * `destination` - The destination IP address to remove
    pub fn remove_route(&self, destination: &IpAddr) {
        if let Some((_, session_id)) = self.routes.remove(destination) {
            // Update reverse mapping
            if let Some(mut ips) = self.reverse.get_mut(&session_id) {
                ips.retain(|ip| ip != destination);
            }
            tracing::debug!(%destination, "Removed route");
        }
    }

    /// Removes all routes for a session.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session ID to remove routes for
    pub fn remove_routes_for_session(&self, session_id: &SessionId) {
        if let Some((_, ips)) = self.reverse.remove(session_id) {
            for ip in ips {
                self.routes.remove(&ip);
            }
            tracing::debug!(session_id = %hex::encode(session_id), "Removed all routes for session");
        }
    }

    /// Looks up the tunnel for a destination IP.
    ///
    /// # Arguments
    ///
    /// * `destination` - The destination IP address to look up
    ///
    /// # Returns
    ///
    /// The session ID of the tunnel, if a route exists.
    pub fn lookup(&self, destination: &IpAddr) -> Option<SessionId> {
        self.routes.get(destination).map(|r| *r.value())
    }

    /// Returns the number of routes in the table.
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Returns true if the routing table is empty.
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Returns all routes as a vector of (destination, session_id) pairs.
    pub fn all_routes(&self) -> Vec<(IpAddr, SessionId)> {
        self.routes
            .iter()
            .map(|r| (*r.key(), *r.value()))
            .collect()
    }

    /// Returns all destinations for a session.
    pub fn destinations_for_session(&self, session_id: &SessionId) -> Vec<IpAddr> {
        self.reverse
            .get(session_id)
            .map(|r| r.value().clone())
            .unwrap_or_default()
    }

    /// Clears all routes.
    pub fn clear(&self) {
        self.routes.clear();
        self.reverse.clear();
    }
}

impl Default for RoutingTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_session_id(n: u8) -> SessionId {
        let mut id = [0u8; 16];
        id[0] = n;
        id
    }

    #[test]
    fn test_add_and_lookup_route() {
        let table = RoutingTable::new();
        let session_id = make_session_id(1);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        table.add_route(ip, session_id);

        assert_eq!(table.lookup(&ip), Some(session_id));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_remove_route() {
        let table = RoutingTable::new();
        let session_id = make_session_id(1);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        table.add_route(ip, session_id);
        assert_eq!(table.len(), 1);

        table.remove_route(&ip);
        assert_eq!(table.lookup(&ip), None);
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn test_remove_routes_for_session() {
        let table = RoutingTable::new();
        let session_id = make_session_id(1);
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();

        table.add_route(ip1, session_id);
        table.add_route(ip2, session_id);
        assert_eq!(table.len(), 2);

        table.remove_routes_for_session(&session_id);
        assert_eq!(table.lookup(&ip1), None);
        assert_eq!(table.lookup(&ip2), None);
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn test_multiple_sessions() {
        let table = RoutingTable::new();
        let session1 = make_session_id(1);
        let session2 = make_session_id(2);
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();

        table.add_route(ip1, session1);
        table.add_route(ip2, session2);

        assert_eq!(table.lookup(&ip1), Some(session1));
        assert_eq!(table.lookup(&ip2), Some(session2));
    }

    #[test]
    fn test_all_routes() {
        let table = RoutingTable::new();
        let session_id = make_session_id(1);
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();

        table.add_route(ip1, session_id);
        table.add_route(ip2, session_id);

        let routes = table.all_routes();
        assert_eq!(routes.len(), 2);
    }

    #[test]
    fn test_destinations_for_session() {
        let table = RoutingTable::new();
        let session_id = make_session_id(1);
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();

        table.add_route(ip1, session_id);
        table.add_route(ip2, session_id);

        let destinations = table.destinations_for_session(&session_id);
        assert_eq!(destinations.len(), 2);
        assert!(destinations.contains(&ip1));
        assert!(destinations.contains(&ip2));
    }

    #[test]
    fn test_clear() {
        let table = RoutingTable::new();
        let session_id = make_session_id(1);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        table.add_route(ip, session_id);
        assert!(!table.is_empty());

        table.clear();
        assert!(table.is_empty());
    }
}
