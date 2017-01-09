### Nmap NSE Scripts
Nmap Script | Port  |   information
---|---|---
mms-identify.nse|	102	|iec-61850-8-1 (mms) ics protocol
s7-enumerate.nse|	102	|numerates Siemens S7 PLC Devices and collects their device information
modbus-discover.nse	|502|	Enumerates SCADA Modbus slave ids (sids) and collects their device information
modicon-info.nse|	502	|use Modbus to communicate to the PLC via Normal queries that are performed via engineering software
cr3-fingerprint.nse|	789|	Fingerprints Red Lion HMI devices
moxa-enum.nse|	4800|	MoxaNPort
melsecq-discover.nse	|5007|	MELSEC-Q Series PLC CPUINFO
melsecq-discover-udp.nse|	5006|	MELSEC-Q Series PLC CPUINFO
BACnet-discover-enumerate.nse |	47808 |	BACnet
atg-info.nse|	10001|	Guardian AST I20100
codesys-v2-discover.nse|	1200/2455|	received then the output will show that the port as CoDeSyS
cspv4-info.nse|	2222|	cspv4-info
dnp3-info.nse|	20000|	DNP3
enip-enumerate.nse|	44818|	Information that is parsed includes Vendor ID, Device Type, Product name, Serial Number, Product code,Revision Number, as well as the Device IP
fox-info.nse|	1911|	collect information from A Tridium Niagara system
omrontcp-info.nse|	9600|	Controller Data Read Command and once a response is received
omronudp-info.nse|	9600|	Controller Data Read Command and once a response is received
pcworx-info.nse	|1962|	PCWorx info
proconos-info.nse|	20547|	ProConOs
Siemens-CommunicationsProcessor.nse | 80 | Checks for SCADA Siemens S7 Communications Processor  devices
Siemens-HMI-miniweb.nse | 80 | Checks for SCADA Siemens SIMATIC S7- devices
Siemens-SIMATIC-PLC-S7.nse | 80 | Checks for SCADA Siemens Simatic S7 devices
Siemens-Scalance-module.nse | 161 | Checks for SCADA Siemens SCALANCE modules
Siemens-WINCC.nse | 137 | Checks for SCADA Siemens WINCC  server
bradford-networks-nac.nse | 8080 | Attempts to detect Bradford Networks Network Sentry appliance admin web interface
iec-identify.nse | 2404 | Attemts to check tcp/2404 port supporting IEC 60870-5-104 ICS protocol
minecraft.nse | 25565 | Checks for Minecraft Servers using the 0x02 "Handshake" protocol
mop-discover.nse | Null | Detect the Maintenance Operation Protocol (MOP) by sending layer 2 DEC DNA Remote Console hello/test messages
stuxnet-detect.nse | 445 |Detects whether a host is infected with the Stuxnet worm

### Other Port

Port | Service
---|---
80 | http
21 | ftp
22 | ssh
23 | telnet
443 | https
4000 | ROC PLus TCP/UDP
50000 | FL-net
771 | RealPort
34980 | 
1089-1091 | 
4840 | 
34962-34964 | 
2123/2152/3386 | GPRS Tunneling
5094 | HART-IP
17185 | Vxworks WDB
37777 | Dahua Dvr
