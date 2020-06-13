# Author: Andres Andreu < http://xri.net/=andres.andreu >
#
# To run:
# python genSSHA_py25.py clear_text_target saltsize
# clear_text_target is the clear text string you want to hash
# saltsize is the size of the salt, traditionally either 4 or 8 bytes
#
# Simple little python2.5 script that will generate salted hashes 
# of the following algorithms:
# sha1(), sha256(), sha384(), and sha512()
# and give you output in base64 form (with and without the {X} identifier) 
# as well as hex

import hashlib, binascii, sys
from base64 import b64encode
from random import randrange

str = sys.argv[1]
saltsize = int(sys.argv[2])

if saltsize <> 4 and saltsize <> 8:
    print "Lets stick to what is out there, 4 or 8 byte salt sizes ...\n\n"
    sys.exit(0)

print "generating simple random salt of %d bytes...\n" % saltsize
salt = ''
for n in range(saltsize/2):
  salt += chr(randrange(256))
salt = binascii.hexlify(salt)

print "SHA1"
m = hashlib.sha1()
m.update(str)
m.update(salt)
h = m.digest()
print "In Hex:\n%s" % binascii.hexlify(h)
w = b64encode( h + salt )
wo = "{SSHA}" + w
print "Base64 encoded:\n%s" % w
print "%s" % wo
print


print "SHA256"
m = hashlib.sha256()
m.update(str)
m.update(salt)
h = m.digest()
print "In Hex:\n%s" % binascii.hexlify(h)
w = b64encode( h + salt )
wo = "{SSHA256}" + w
print "Base64 encoded:\n%s" % w
print "%s" % wo
print


print "SHA384"
m = hashlib.sha384()
m.update(str)
m.update(salt)
h = m.digest()
print "In Hex:\n%s" % binascii.hexlify(h)
w = b64encode( h + salt )
wo = "{SSHA384}" + w
print "Base64 encoded:\n%s" % w
print "%s" % wo
print


print "SHA512"
m = hashlib.sha512()
m.update(str)
m.update(salt)
h = m.digest()
print "In Hex:\n%s" % binascii.hexlify(h) 
w = b64encode( h + salt )
wo = "{SSHA512}" + w
print "Base64 encoded:\n%s" % w
print "%s" % wo
print

