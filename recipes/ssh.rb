# This was a sample recipe from a tutorial that I followed.
# 
# In the end, I chose to do it differently.
#
# Have we decided to lock down the node?
if node[:iptables][:ssh][:addresses].empty?
  # Use the all_ssh rule
  iptables_rule "all_ssh"
  # Disable the network ssh rule
  iptables_rule "network_ssh", :enable => false
else
  # Use the network rule
  iptables_rule "network_ssh"
  # Disable the all traffic rule
  iptables_rule "all_ssh", :enable => false
end
iptables_rule "defaults"
