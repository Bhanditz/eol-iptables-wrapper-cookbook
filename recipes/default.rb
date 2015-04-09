include_recipe "iptables"

iptables_rule "defaults" do
  action :enable
end
