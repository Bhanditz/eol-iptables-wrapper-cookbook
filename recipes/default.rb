include_recipe "iptables"

iptables_rule "all_established"
iptables_rule "all_icmp"

