import logging
import struct

from collections import namedtuple

from . import ethernetip as enip

LOG = logging.getLogger(__file__)

# ip helpers
def IP2Int(ip):
	o = map(int, ip.split('.'))
	res = (16777216 * o[0]) + (65536 * o[1]) + (256 * o[2]) + o[3]
	return res

def Int2IP(ipnum):
	o1 = int(ipnum / 16777216) % 256
	o2 = int(ipnum / 65536) % 256
	o3 = int(ipnum / 256) % 256
	o4 = int(ipnum) % 256
	return '%(o1)s.%(o2)s.%(o3)s.%(o4)s' % locals()

def PrettyMAC(mac):
	return "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB", mac)
#	return ':'.join('%02x' % ord(b) for b in mac_string)

# -- Command line interface --
import cmd

class ScannerShell(cmd.Cmd):
	prompt = '(dlr) '

	def __init__(self):
		cmd.Cmd.__init__(self)

	def do_quit(self, arg):
		"Quits the scanner"
		return True
	
	def do_scan(self, arg):
		"Scan a DLR ring: scan [ip]"

		args = arg.split()
		if len(args) != 1:
			print("Invalid number of arguments.")
			return

		scan_ip = args[0]
		eip = enip.EtherNetIP(scan_ip)
		c1 = eip.explicit_conn()
		c1.registerSession()

		r = c1.getAttrSingle(enip.CIP_OBJ_DLR, 1, 1)
		assert r[0] == 0

		if r[1] == b'\x00':
			print("Device is not in a ring topology")
			return

		# read out active supervisor address
		r = c1.getAttrSingle(enip.CIP_OBJ_DLR, 1, 10)
		assert r[0] == 0
		c1.unregisterSession()
		
		assert len(r[1]) == 10
		tmp_ip, supervisor_mac = struct.unpack("<L6s", r[1])
		supervisor_ip = Int2IP(tmp_ip)

		print("   Supervisor-IP: {}".format(supervisor_ip))

		eip = enip.EtherNetIP(supervisor_ip)
		c1 = eip.explicit_conn()
		c1.registerSession()
		# participant count 
		r = c1.getAttrSingle(enip.CIP_OBJ_DLR, 1, 8)
		assert r[0] == 0
		assert len(r[1]) == 2
		participant_count, = struct.unpack("<H", r[1])
		print("   Participant count: {}".format(participant_count))
		
		# ring faults count
		r = c1.getAttrSingle(enip.CIP_OBJ_DLR, 1, 5)
		assert r[0] == 0
		assert len(r[1]) == 2
		faults_count, = struct.unpack("<H", r[1])
		print("   Ring Fault Count: {}".format(faults_count))
		
		# read out devices
		# ip and mac
		r = c1.getAttrSingle(enip.CIP_OBJ_DLR, 1, 9)
		assert r[0] == 0
	
		participants = []

		Participant = namedtuple('Participant', 'ip mac product_name revision port1 port2')
		for i in range(participant_count):
			participant = r[1][i*10:i*10+10]
			tmp_ip, tmp_mac = struct.unpack("<L6s", participant)
			p_ip = Int2IP(tmp_ip)
			p_eip = enip.EtherNetIP(p_ip)
			p_c1 = p_eip.explicit_conn()
			p_c1.registerSession()
			p_r = p_c1.getAttrSingle(enip.CIP_OBJ_IDENTITY, 1, 7)
			assert p_r[0] == 0
			product_name = p_r[1][1:].decode()

			p_r = p_c1.getAttrSingle(enip.CIP_OBJ_IDENTITY, 1, 4)
			assert p_r[0] == 0
			assert len(p_r[1]) == 2
			rev_major, rev_minor = struct.unpack("BB", p_r[1])
			revision = "{}.{}".format(rev_major, rev_minor)
		

			# request port stuff
			ports = []
			for port in range(2):
				p_r = p_c1.getAttrSingle(enip.CIP_OBJ_ETHERNET_LINK, port+1, 1)
				assert p_r[0] == 0
				assert len(p_r[1]) == 4
				iface_speed, = struct.unpack("<L", p_r[1])

				p_r = p_c1.getAttrSingle(enip.CIP_OBJ_ETHERNET_LINK, port+1, 2)
				assert p_r[0] == 0
				assert len(p_r[1]) == 4
				iface_flags, = struct.unpack("<L", p_r[1])

				if iface_flags & 0x01:
					s = str(iface_speed)
					if iface_flags&0x02:
						s += "FDX"
					else:
						s += "HDX!"
					p_r = p_c1.getAttrSingle(enip.CIP_OBJ_ETHERNET_LINK, port+1, 5)
					assert p_r[0] == 0
					assert len(p_r[1]) == 48
					align, fcs, scol, mcol, sqe, deft, lcol, ecol, mtx, cs, ftl, mrx = struct.unpack("<LLLLLLLLLLLL", p_r[1])
					if align > 0:
						s += "|ALG"
					if fcs > 0:
						s += "|FCS"
					if scol > 0:
						s += "|SCOL"
					if mcol > 0:
						s += "|MCOL"
					
					ports.append(s)
				else:
					ports.append("NoLink")

			p_c1.unregisterSession()
			participants.append(Participant(ip=p_ip, mac=PrettyMAC(tmp_mac), product_name=product_name, revision=revision, port1=ports[0], port2=ports[1]))

		print()
		print("{:16s} {:18s} {:10s} {:10s} {:32s} {:5s}".format(
			"IP",
			"MAC",
			"Port1",
			"Port2",
			"Product name",
			"Rev"))
		print("=============================================================================================================")

		for dev in participants:
			print("{:16s} {:18s} {:10s} {:10s} {:32s} {:5s}".format(
				dev.ip,
				dev.mac,
				dev.port1,
				dev.port2,
				dev.product_name,
				dev.revision))
		c1.unregisterSession()
		

def main():
	import argparse
	parser = argparse.ArgumentParser(description="DLR scanner command line client")
	parser.add_argument("-v", "--verbose", action="store_true", help="enable verbose output")
	parser.add_argument("-vv", action="store_true", help="enable very verbose output")

	args = parser.parse_args()

	if args.vv:
		args.verbose = True
	if args.verbose:
		level = logging.INFO
		if args.vv:
			level = logging.DEBUG

		verbose_handler = logging.StreamHandler()
		verbose_handler.setLevel(level)

		logging.getLogger().setLevel(level)
		logging.getLogger().addHandler(verbose_handler)

	ScannerShell().cmdloop()

if __name__ == "__main__":
	main()

