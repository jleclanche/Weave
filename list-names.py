#!/usr/bin/python
# -*- coding: utf-8 -*-

"""Simple example script that dumps all encountered player names inside a logfile."""

from log import *
from cStringIO import StringIO
from utils import *

import sys
import opcodes

sys.argv.pop(0)

for filename in sys.argv:
	if filename == "-":
		file = sys.stdin
	else:
		file = open(filename, "rb")
	
	for entry in Log(file):
		if isinstance(entry, Message) and entry.opcode == opcodes.SMSG_NAME_QUERY_RESPONSE:
			stream = StringIO(entry.data)
			
			guid = readGUID(stream)
			stream.read(1)
			name = readstring(stream, encoding="utf-8")
			
			print hex(guid), repr(name)