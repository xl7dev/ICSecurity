#!/usr/bin/python  
# version 2.7
import socket,thread
from array import array
from time import sleep, ctime
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('',502))
s.listen(1)
F = open('modbus.log', 'w', 0)
def TCP(conn,addr,F):
  buffer = array('B',[0]*300)
  while 1:
    try:
      conn.recv_into(buffer)
      ID = buffer[6]
      FC = buffer[7]
      mADR = buffer[8]
      lADR = buffer[9]
      ADR = mADR*256+lADR
      LEN = buffer[10]*256+buffer[11]
      BYT = LEN*2
      print "Received = ",buffer[0:13+buffer[12]]
      if (FC < 5 and FC > 0):   #Read Inputs or Registers
        DAT = array('B')
        if FC < 3: 
          BYT = (lambda x: x/8 if (x%8==0) else x/8+1)(LEN)     #Round off the no. of bytes
          v = 85          #send 85,86.. for bytes.
          for i in range(BYT): 
            DAT.append(v)
            v = (lambda x: x+1 if (x<255) else 85)(v)
        else:
          for i in range(LEN):  #Sends back the address as data
            DAT.append(mADR)
            DAT.append(lADR)
            if (lADR == 255):
              lADR = 0
              mADR = mADR + 1
            else: lADR = lADR + 1
        print "ID= %d,  Fun.Code= %d,  Address= %d,  Length= %d" %(ID, FC, ADR, LEN)
        conn.send(array('B', [0,0,0,0,0, BYT+3, ID, FC, BYT]) + DAT )
      elif (FC == 15 or FC == 16 or FC == 6):    #Write Registers
        BYT = buffer[12]
        conn.send(array('B', [0,0,0,0,0, 6, ID, FC, mADR, lADR, buffer[10], buffer[11] ] ) )
        buf = buffer[13:(13+BYT)]
        message = ': ADR:'+str(ADR)+' '
        if FC == 15:
          print "ID= %d,  Fun.Code= %d,  Address= %d,  Length= %d,  Bytes= %d" %(ID, FC, ADR, LEN, BYT)
          for j in range(BYT):  message = message+('Byte:'+str(j)+'='+str(buf[j])+', ')
        elif FC == 16:
          print "ID= %d,  Fun.Code= %d,  Address= %d,  Length= %d,  Bytes= %d" %(ID, FC, ADR, LEN, BYT)
          for j in range(BYT/2): message = message+('Reg:'+str(j)+'='+str((buf[j*2]<<8)+(buf[j*2+1]))+', ')
        elif FC == 6:
          print "ID= %d,  Fun.Code= %d,  Address= %d, Bytes= %d" %(ID, FC, ADR, LEN)
          message = message+('Reg:'+str(LEN))  
        print message
        F.write(ctime() + message + "\n")
      else: 
        print "Funtion Code %d Not Supported" %FC
        exit()
      sleep(1)
    except Exception, e:
      print e, "\nConnection with Client terminated" 
      exit()
while 1:
  conn, addr = s.accept()
  print "Connected by", addr[0]
  thread.start_new_thread(TCP,(conn,addr,F))
