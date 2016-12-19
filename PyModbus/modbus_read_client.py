#!/usr/bin/python  
# version 2.7
import socket
from sys import argv,exit
from array import array
from time import sleep
if len(argv) < 6 or argv[1] == '-h' or argv[1] == '--help' or argv[1] == '?':
  print "usage: python modbus_read_client.py Host Unit FC Address Length"
  exit()
HOST = argv[1]  # The remote host
#HOST = '192.168.5.30'  # The remote host
PORT = 502    # The same port as used by the server
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
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
cmd = array('B', [00,00,00,00,00,06,UNIT,FC,mADD,lADD,mLEN,lLEN])
while 1:
  s.send(cmd)
  buffer = array('B', [0]*(BYT+9))
  s.recv_into(buffer)
  buf = buffer[9:(9+BYT)]
  print 'Received', buffer
  if (FC > 2): 
    for j in range(BYT/2):
      #print 'data for Reg',(BYT/2)-1-j,'=', (buffer[(-j*2)-2]<<8)+buffer[(-j*2)-1]
      print 'data for Reg',j,'=', (buf[(j*2)]<<8)+buf[j*2+1]
  else:
    for j in range(BYT):
      #print 'data for Bytes',BYT-1-j,'=', buffer[-1-j]
      print 'data for Byte',j,'=', buf[j]
  sleep(1)


