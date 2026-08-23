use super::FirewallRules;

#[allow(dead_code)]
pub fn render(rules: &FirewallRules) -> String {
    let mut out = String::new();
    for cidr in &rules.allow_cidrs {
        out.push_str(&format!(
            "pass out on {} from any to {} keep state\n",
            rules.tun_name, cidr
        ));
    }
    if rules.block_default {
        out.push_str("block out all\n");
    }
    out
}
