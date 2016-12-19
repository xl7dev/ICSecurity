#!/usr/bin/python  
# version 2.7
import socket
from sys import argv,exit
from array import array
from time import sleep
if len(argv) < 6 or argv[1] == '-h' or argv[1] == '--help' or argv[1] == '?':
  print "usage: python modbus_write_client.py Host Unit FC Address Data[1...n]"
  exit()
PORT = 502    # The same port as used by the server
HOST = argv[1]  # The remote host
UNIT = int(argv[2])
FC = int(argv[3])
ADD = int(argv[4])
val = []
for v in range(5,len(argv)):
  val.append(int(argv[v]))
VAL = []
for i in val:
  VAL.append((int(i) & 0xFF00)>>8)
  VAL.append(int(i) & 0x00FF)
if (FC == 5 or FC == 15): LEN = len(VAL)*8
else: LEN = len(VAL)/2
lADD = ADD & 0x00FF
mADD = ADD >> 8
lLEN = LEN & 0x00FF
mLEN = LEN >> 8
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
if (FC == 6 or FC == 5):
  cmd = array('B', [00,00,00,00,00,6,UNIT,FC,mADD,lADD])
else:
  cmd = array('B', [00,00,00,00,00,7+len(VAL),UNIT,FC,mADD,lADD,mLEN,lLEN,len(VAL)])
for i in VAL:
  cmd.append(i)
buffer = array('B', [0]*20)
try:
 while 1:
  print "Send", cmd
  s.send(cmd)
  s.recv_into(buffer)
  print 'Received', buffer[:12]
  sleep(1)
except Exception: exit()

