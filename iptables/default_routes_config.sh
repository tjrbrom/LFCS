systemctl disable --now firewalld
systemctl enable --now iptables

# remove current conf
iptables -F INPUT
iptables -F OUTPUT

iptables -P INPUT DROP
iptables -P OUTPUT DROP

# enable incoming ssh and ping
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT
iptables -A OUTPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# enable outgoing ssh, dns, ping and http
iptables -A OUTPUT -p icmp -j ACCEPT
iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT

iptables -L

# save and persist the configuration
iptables-save
iptables-save > /etc/sysconfig/iptables

