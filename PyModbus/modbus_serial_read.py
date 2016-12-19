#!/usr/bin/python  
# version 2.7
# Read Modbus RTU Serial 
from serial import Serial
from sys import argv,exit
from struct import pack_into
from array import array
from time import sleep
from struct import unpack
if len(argv) < 6 or argv[1] == '-h' or argv[1] == '--help' or argv[1] == '?':
  print "usage: python modbus_rtu_read.py Port Unit FC Address Length"
  exit()
def CRC(list):
  crc = 0xffff
  for l in list:
    c = l ^ crc
    for i in range (8):
      if (c & 0x0001) != 0:
        c = c >> 1
        c = c ^ 0xA001
      else:
        c = c >> 1
    crc = c
  b = array('B',[0]*2)
  pack_into('H',b,0,crc)
  return b
PORT =  argv[1]   
UNIT = int(argv[2])
FC = int(argv[3])
ADD = int(argv[4])
LEN = int(argv[5])
lLEN = LEN & 0x00FF
mLEN = LEN >> 8
if (FC < 3): BYT = (lambda x: x/8 if (x%8==0) else x/8+1)(LEN)    #Round off the no. of bytes
else: BYT = LEN*2
lADD = ADD & 0x00FF
mADD = (ADD & 0xFF00)>>8
s = Serial('/dev/'+PORT, timeout=0.5)
s.baudrate = 9600
s.parity = "E"
s.databits = 8
s.stopbits = 1
s.handshake = "none"
s.datatype = "raw"
cmd = array('B', [UNIT,FC,mADD,lADD,mLEN,lLEN])
cmd.extend(CRC(cmd))
#lcrc = crc & 0x00FF
#mcrc = (crc & 0xFF00)>>8
#cmd = array('B', [UNIT,FC,mADD,lADD,mLEN,lLEN,lcrc,mcrc]) 
while 1:
  s.write(cmd)
  print cmd
  sleep(1)
  read = s.read(255)
  r = ''
  if len(read) > 0: r = unpack('B'*len(read),read)
  print 'Received =', r 
#  s.flushInput()
#  s.flushOutput()
  sleep(0.5)
