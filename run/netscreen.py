# netscreen.py
# Generate passwords in netscreen format.
# 

import md5
import sys

def net(user, password):
  b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  middle = "Administration Tools"
  s = "%s:%s:%s" % (user, middle, password)
  m = md5.new(s).digest()

  narray = []
  for i in range(8):
    n1 = ord(m[2*i])
    n2 = ord(m[2*i+1])
    narray.append( (n1<<8 & 0xff00) | (n2 & 0xff) )

  res = ""
  for i in narray:
    p1 = i >> 12 & 0xf
    p2 = i >> 6  & 0x3f
    p3 = i       & 0x3f
    res = res + b64[p1] + b64[p2] + b64[p3]

  for c, n in  zip("nrcstn", [0, 6, 12, 17, 23, 29]):
	  res = res[:n] + c + res[n:]
  return res


if __name__ == '__main__':
  user = sys.argv[1]
  password = sys.argv[2]

  ciphertext = net(user,password)
  print "%s:%s$%s" % (user,user,ciphertext)
