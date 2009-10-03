#!/usr/bin/python
# -*- coding: utf-8 -*-

"""Simple example script that dumps all encountered player names inside a logfile."""

from __future__ import with_statement
from log import *
from cStringIO import StringIO
from utils import *

import sys
import opcodes

from optparse import OptionParser

def main():
	parser = OptionParser(usage="usage: %prog [INPUT]", description=__doc__)
	(options, args) = parser.parse_args()
	
	if not len(args):
		args.append("-")
	
	for filename in args:
		if filename == "-":
			file = sys.stdin
		else:
			file = open(filename, "rb")
		
		with file:
			for entry in Log(file):
				if isinstance(entry, Message) and entry.opcode == opcodes.SMSG_NAME_QUERY_RESPONSE:
					stream = StringIO(entry.data)
					
					guid = readGUID(stream)
					stream.read(1)
					name = readstring(stream, encoding="utf-8")
					
					print hex(guid), repr(name)

if __name__ == "__main__":
	main()