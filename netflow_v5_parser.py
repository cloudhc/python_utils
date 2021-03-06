import socket, struct

from socket import inet_ntoa

SIZE_OF_HEADER = 24
SIZE_OF_RECORD = 48

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', 5555))

while True:
  buf, addr = sock.recvfrom(1500)

  (version, count) = struct.unpack('!HH',buf[0:4])
  if version != 5:
    print "Not NetFlow v5!"
    continue

  # It's pretty unlikely you'll ever see more then 1000 records in a 1500 byte UDP packet
  if count <= 0 or count >= 1000:
    print "Invalid count %s" % count
    continue

  uptime = socket.ntohl(struct.unpack('I',buf[4:8])[0])
  epochseconds = socket.ntohl(struct.unpack('I',buf[8:12])[0])

  for i in range(0, count):
    try:
      base = SIZE_OF_HEADER+(i*SIZE_OF_RECORD)

      data = struct.unpack('!IIIIHH',buf[base+16:base+36])

      nfdata = {}
      nfdata['saddr'] = inet_ntoa(buf[base+0:base+4])
      nfdata['daddr'] = inet_ntoa(buf[base+4:base+8])
      nfdata['pcount'] = data[0]
      nfdata['bcount'] = data[1]
      nfdata['stime'] = data[2]
      nfdata['etime'] = data[3]
      nfdata['sport'] = data[4]
      nfdata['dport'] = data[5]
      nfdata['protocol'] = ord(buf[base+38])
  except:
    continue

  # Do something with the netflow record..
  print "%s:%s -> %s:%s" % (nfdata['saddr'],nfdata['sport'],nfdata['daddr'],nfdata['dport'])
