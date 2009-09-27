from __future__ import with_statement

class _nameclass(dict):
	def __getitem__(self, item):
		if item in self:
			return dict.__getitem__(self, item)
		else:
			return "UMSG_UNKNOWN_%d" % item

names = _nameclass()

try:
	import re

	with open("Opcodes.h", "r") as opcode_file:
		opcode_contents = opcode_file.read()

	for match in re.finditer(r"\s+([^\s]+)\s*=\s*(0x.+?)\s*,", opcode_contents):
		name = match.group(1)
		code = eval(match.group(2))
		
		globals()[name] = code
		names[code] = name
except:
	pass
