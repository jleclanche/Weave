#!/usr/bin/python
# -*- coding: utf-8 -*-

"""Unpacks a Weave logfile by creating one file for each message, e.g.
000001.CMSG_AUTH_SESSION.wmsg, thereby allowing the file to be easily
inspected using other applications, such as hex editors.

If opcode names are given as extra parameters beyond the filename, only
messages with that opcode are extracted."""

from __future__ import with_statement
from weave import *
from optparse import OptionParser
from zlib import decompress
import os

def main():
	parser = OptionParser(usage="usage: %prog [options] LOGFILE [OPCODE1] [OPCODE2] ...", description=__doc__)
	parser.add_option("-o", "--output-dir", dest="outdir", help="output to directory DIR. By default, the input filename is used as the name for the output directory.", metavar="DIR", type="str")
	(options, args) = parser.parse_args()

	if len(args) < 1:
		parser.error("Not enough arguments")

	filename = args.pop(0)

	if options.outdir:
		outdir = options.outdir
	else:
		part = filename.rpartition(".wlog")
		outdir = part[0] or part[2]

	try:
		os.makedirs(outdir)
	except os.error:
		pass
	
	counter = 0
	
	with open(filename, "rb") as file:
		for message in Log(file):
			if not isinstance(message, Message):
				continue
			
			counter += 1
			
			if len(args) and opcodes[message.opcode] not in args:
				continue
			
			msg_filename = "%06d.%s.wmsg" % (counter, opcodes[message.opcode])
			msg_full_filename = os.path.join(outdir, msg_filename)
			
			with open(msg_full_filename, "wb") as msg_file:
				if message.opcode == SMSG_COMPRESSED_UPDATE_OBJECT:
					data = decompress(message.data[4:])
				else:
					data = message.data
				
				msg_file.write(data)
			
			print msg_full_filename

if __name__ == "__main__":
	main()