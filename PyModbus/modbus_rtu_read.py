#!/usr/bin/python  
# version 2.7
# Read Modbus RTU over TCP Port Server
import socket
from sys import argv,exit
from array import array
from time import sleep
if len(argv) < 7 or argv[1] == '-h' or argv[1] == '--help' or argv[1] == '?':
  print "usage: python modbus_rtu_read.py Host Port Unit FC Address Length"
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
  return crc
HOST = argv[1] 
PORT =  int(argv[2])   
UNIT = int(argv[3])
FC = int(argv[4])
ADD = int(argv[5])
LEN = int(argv[6])
lLEN = LEN & 0x00FF
mLEN = LEN >> 8
if (FC < 3): BYT = (lambda x: x/8 if (x%8==0) else x/8+1)(LEN)    #Round off the no. of bytes
else: BYT = LEN*2
lADD = ADD & 0x00FF
mADD = (ADD & 0xFF00)>>8
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
cmd = array('B', [UNIT,FC,mADD,lADD,mLEN,lLEN])
crc = CRC(cmd)
lcrc = crc & 0x00FF
mcrc = (crc & 0xFF00)>>8
cmd = array('B', [UNIT,FC,mADD,lADD,mLEN,lLEN,lcrc,mcrc]) 
while 1:
  s.send(cmd)
  buffer = array('B', [0]*(BYT+7))
  s.recv_into(buffer)
  buf = buffer[3:(3+BYT)]
  print 'Received', buffer
  if (FC > 2): 
    for j in range(BYT/2):
      #print 'data for Reg',(BYT/2)-1-j,'=', (buffer[(-j*2)-2]<<8)+buffer[(-j*2)-1]
      print 'data for Reg',j,'=', (buf[(j*2)]<<8)+buf[j*2+1]
  else:
    for j in range(BYT):
      #print 'data for Bytes',BYT-1-j,'=', buffer[-1-j]
      print 'data for Byte',j,'=', buf[j]
  sleep(2)
