#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
import structures
from cStringIO import StringIO
from struct import unpack
from weave import *

def ispacket(packet, cls):
	return isinstance(packet, Message) and packet.opcode == cls

def hexdump(src, length=16):
	result = []
	digits = 4 if isinstance(src, unicode) else 2
	for i in xrange(0, len(src), length):
		s = src[i:i+length]
		hexa = b' '.join(["%0*X" % (digits, ord(x))  for x in s])
		text = b''.join([x if 0x20 <= ord(x) < 0x7F else b'.'  for x in s])
		result.append( b"%04X   %-*s   %s" % (i, length*(digits + 1), hexa, text) )
	return b'\n'.join(result)

def main():
	f = open(sys.argv[1], "rb")

	build = iter(Log(f)).next().build
	for packet in Log(f):
		if ispacket(packet, SMSG_AUCTION_LIST_RESULT):
			structure = structures.SMSG_AUCTION_LIST_RESULT(build=build)
			data = StringIO(packet.data)
			entry_count, = unpack("<I", data.read(4))
			rows = []
			for i in range(entry_count):
				row = {}
				for col in structure:
					_data, = unpack("<%s" % (col.char), data.read(col.size))
					row[col.name] = col.to_python(_data, None)
				rows.append(row)
			print unpack("<ii", data.read()) # whats this?
		
		#elif ispacket(packet, SMSG_REALM_SPLIT):
			#print packet
			#print hexdump(packet.data)
			#f = open(opcodes[packet.opcode], "wb")
			#f.write(packet.data)
			#f.close()
		elif ispacket(packet, SMSG_ITEM_QUERY_SINGLE_RESPONSE):
			if len(packet.data) <= 4:
				continue
			structure = structures.ItemCache(build=build)
			data = StringIO(packet.data)
			row = {}
			dyns = 0
			for field in structure:
				if isinstance(field, structures.RecLenField):
					continue
				
				if field.dyn > dyns:
					_data = None
				
				elif isinstance(field, structures.StringField):
					_data = []
					while True:
						c = data.read(1)
						if c == "\x00":
							break
						_data.append(c)
					_data = "".join(_data)
				
				elif isinstance(field, structures.DynamicMaster):
					_data, = unpack("<%s" % (field.char), data.read(field.size))
					dyns = _data
				
				else:
					_data, = unpack("<%s" % (field.char), data.read(field.size))
				
				row[field.name] = _data
		
		
		#elif isinstance(packet, Message):
			#print packet, opcodes[packet.opcode]

if __name__ == "__main__":
	main()
