from cStringIO import StringIO
from datetime import datetime
from operator import attrgetter
from socket import inet_aton, inet_ntoa
from struct import Struct, pack, unpack, error as StructError
from time import time
from utils import readstring

import opcodes

class SessionInfo(object):
	type_code = 0x00
	struct = Struct("<4s3BH4s4sH4sH")
	
	def __init__(self, game, version, locale, client, server, account):
		self.game = game.strip(chr(0))
		self.version = version
		self.locale = locale.strip(chr(0))
		self.client = client
		self.server = server
		self.account = account.strip(chr(0))
	
	@classmethod
	def unpack(cls, data):
		game, major, minor, revision, build, locale, client_ip, client_port, server_ip, server_port = SessionInfo.struct.unpack_from(data)
		account = unicode(readstring(data, SessionInfo.struct.size))
		client = (inet_ntoa(client_ip), client_port)
		server = (inet_ntoa(server_ip), server_port)
		return cls(game, (major, minor, revision, build), locale, client, server, account)
	
	def pack(self):
		args = (self.game,) + self.version + (self.locale, inet_aton(self.client[0]), self.client[1], inet_aton(self.server[0]), self.server[1])
		return self.struct.pack(*args) + self.account.encode("utf8") + chr(0)
	
	def __repr__(self):
		return "<Session Info: %s %d.%d.%d (Build %d) %s, account = %s, client = %s:%d, server = %s:%d>" % (self.game, self.version[0], self.version[1], self.version[2], self.version[3], self.locale, self.account, self.client[0], self.client[1], self.server[0], self.server[1])

class Message(object):
	struct = Struct("<L4sH4sH")
	
	def __init__(self, opcode, client, server, data):
		self.opcode = opcode
		self.client = client
		self.server = server
		self.data = data

	@classmethod
	def unpack(cls, data):
		opcode, client_ip, client_port, server_ip, server_port = Message.struct.unpack_from(data)
		client = (inet_ntoa(client_ip), client_port)
		server = (inet_ntoa(server_ip), server_port)
		content = data[Message.struct.size:]
		return cls(opcode, client, server, content)
	
	def pack(self):
		client_ip, client_port = inet_aton(self.client[0]), self.client[1]
		server_ip, server_port = inet_aton(self.server[0]), self.server[1]
		
		args = (self.opcode, client_ip, client_port, server_ip, server_port)
		return self.struct.pack(*args) + self.data
	
	def __repr__(self):
		name = opcodes.names[self.opcode]
		
		if len(self.data) > 0:
			return "<%s: %d data bytes>" % (name, len(self.data))
		else:
			return "<%s>" % (name,)

class ClientMessage(Message):
	type_code = 0x01	

class ServerMessage(Message):
	type_code = 0x02

type_codes = {
	0x00: SessionInfo,
	0x01: ClientMessage,
	0x02: ServerMessage,
}

class Log(object):
	IDENT = "WeaveLog"
	VERSION = 1
	
	HEADER_SIZE = 32
	header_struct = Struct("<8sH")
	
	MESSAGE_HEADER_SIZE = 6
	message_header_struct = Struct("<HL")
	
	def __init__(self, stream):
		self._stream = stream
		
		if "r" in getattr(stream, "mode", "r"):
			self._stream.seek(0)
			header = self._stream.read(self.HEADER_SIZE)
			
			if len(header) >= Log.header_struct.size:
				ident, dump_version = self.header_struct.unpack_from(header)

				if ident != self.IDENT:
					print ident
					raise ValueError("Unknown header")
				
				if dump_version != self.VERSION:
					raise ValueError("Unsupported version")

	def write_header(self):
		self._stream.write(self.header_struct.pack(self.IDENT, self.VERSION).ljust(self.HEADER_SIZE, chr(0)))
		self._stream.flush()
	
	def next(self):
		header = self._stream.read(self.MESSAGE_HEADER_SIZE)
		
		if len(header) < self.MESSAGE_HEADER_SIZE:
			return
		
		type_code, size = self.message_header_struct.unpack_from(header)
		
		data = self._stream.read(size)
		
		if type_code in type_codes:
			return type_codes[type_code].unpack(data)
	
	def __iter__(self):
		self._stream.seek(self.HEADER_SIZE)
		while True:
			next_item = self.next()
			
			if next_item:
				yield next_item
			else:
				break

	def write(self, message):
		packed = message.pack()
		self._stream.write(self.message_header_struct.pack(message.type_code, len(packed)) + packed)
		self._stream.flush()