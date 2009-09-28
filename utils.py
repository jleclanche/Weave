from struct import unpack

def readGUID(buf):
	guid_zeroes, = unpack("<B", buf.read(1))
	guid_inflated = ""

	for i in range(8):
		if guid_zeroes & 0x1:
			guid_inflated += buf.read(1)
		else:
			guid_inflated += chr(0)

		guid_zeroes >>= 1
	
	return unpack("<Q", guid_inflated)[0]

def readstring(buf, offset=0, encoding=None):
	"""Read from string or StringIO buffer until EOF or a null char is encountered."""
	tmp = ""
	index = offset
	while True:
		if type(buf) in (str, unicode):
			c = buf[index]
		else:
			c = buf.read(1)
		
		if c == chr(0) or len(c) == 0:
			if encoding:
				return unicode(tmp, encoding)
			else:
				return tmp
		
		tmp += c
		index = index + 1

def hexdump(src, length=16):
    result = []
    digits = 4 if isinstance(src, unicode) else 2
    for i in xrange(0, len(src), length):
       s = src[i:i+length]
       hexa = b' '.join(["%0*X" % (digits, ord(x))  for x in s])
       text = b''.join([x if 0x20 <= ord(x) < 0x7F else b'.'  for x in s])
       result.append( b"%04X   %-*s   %s" % (i, length*(digits + 1), hexa, text) )
    return b'\n'.join(result)