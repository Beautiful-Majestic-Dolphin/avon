use super::FirewallRules;

/// Removing a table that was never created is an error in nft, so the table is
/// declared before it is deleted — the pair is idempotent.
pub const CLEAR: &str = "table inet avon\ndelete table inet avon\n";

#[allow(dead_code)]
pub fn render(rules: &FirewallRules) -> String {
    let mut out = String::new();
    out.push_str("table inet avon {\n");
    out.push_str("  chain forward {\n");
    out.push_str("    type filter hook forward priority 0; policy drop;\n");
    for cidr in &rules.allow_cidrs {
        out.push_str(&format!("    ip daddr {cidr} accept\n"));
    }
    out.push_str(&format!("    oifname \"{}\" accept\n", rules.tun_name));
    if rules.block_default {
        out.push_str("    drop\n");
    }
    out.push_str("  }\n");
    out.push_str("}\n");
    out
}
