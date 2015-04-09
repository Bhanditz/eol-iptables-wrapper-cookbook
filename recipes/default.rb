include_recipe "simple_iptables"

# Always allow ssh (for now--we will whitelist this later, I suspect):
simple_iptables_rule "ssh" do
  rule "--proto tcp --dport 22"
  jump "ACCEPT"
end

# Check for protocols:

@node[:iptables][:allow_protocols].each do |protocol|
  case "http"
    simple_iptables_rule protocol do
      rule "--proto tcp --dport 80"
      jump "ACCEPT"
    end
  case "https"
    simple_iptables_rule protocol do
      rule "--proto tcp --dport 443"
      jump "ACCEPT"
    end
  case "http_8080"
    simple_iptables_rule protocol do
      rule "--proto tcp --dport 8080"
      jump "ACCEPT"
    end
  case "https_8081"
    simple_iptables_rule protocol do
      rule "--proto tcp --dport 8081"
      jump "ACCEPT"
    end
  case "https_8082"
    simple_iptables_rule protocol do
      rule "--proto tcp --dport 8082"
      jump "ACCEPT"
    end
  case "https_8083"
    simple_iptables_rule protocol do
      rule "--proto tcp --dport 8083"
      jump "ACCEPT"
    end
  case "rsync"
    simple_iptables_rule protocol do
      rule "--proto tcp --dport 22"
      jump "ACCEPT"
    end
  case "redis"
    simple_iptables_rule protocol do
      rule "--proto tcp --dport 6379"
      jump "ACCEPT"
    end
  case "memcached"
    simple_iptables_rule protocol do
      rule "--proto tcp --dport 11211"
      jump "ACCEPT"
    end
  case "solr"
    simple_iptables_rule protocol do
      rule "--proto tcp --dport 8983"
      jump "ACCEPT"
    end
  case "rabbit-mq"
    simple_iptables_rule protocol do
      rule "--proto tcp --dport 5671"
      jump "ACCEPT"
    end
  case "node.js"
    simple_iptables_rule protocol do
      rule "--proto tcp --dport 3000"
      jump "ACCEPT"
    end
  case "mysql"
    simple_iptables_rule protocol do
      rule "--proto tcp --dport 3306"
      jump "ACCEPT"
    end
  case "sysopia"
    simple_iptables_rule protocol do
      rule "--proto tcp --dport 9999"
      jump "ACCEPT"
    end
  case "virtuoso"
    simple_iptables_rule protocol do
      rule ["--proto tcp --dport 1111",
            "--proto tcp --dport 8890"]
      jump "ACCEPT"
    end
  else
    raise "I do not understand the #{protocol} protocol."
  end
end

# Some intelligent defaults:

simple_iptables_rule "established" do
  rule "-m conntrack --ctstate ESTABLISHED,RELATED"
  jump "ACCEPT"
end

simple_iptables_rule "ping" do
  rule "--proto icmp"
  jump "ACCEPT"
end

simple_iptables_rule "local" do
  rule "--in-interface lo"
  jump "ACCEPT"
end

simple_iptables_rule "conntrack ssh" do
  rule "--proto tcp --dport 22 -m conntrack --ctstate NEW"
  jump "ACCEPT"
end

simple_iptables_rule "prohibited" do
  rule "--reject-with icmp-host-prohibited"
  jump "REJECT"
end

simple_iptables_rule "forward prohibited" do
  direction "FORWARD"
  rule "--reject-with icmp-host-prohibited"
  jump "REJECT"
end

simple_iptables_policy "INPUT" do
  policy "REJECT"
end

