from cStringIO import StringIO
from datetime import datetime
from socket import inet_aton, inet_ntoa
from struct import *
from utils import *
from wowguid import *


import opcodes

class Message(object):
	struct = Struct("<L4sH4sH")
	
	def __new__(cls, opcode, client, server, data):
		opcode_name = opcodes.names[opcode]
		
		if opcode_name in globals():
			cls = globals()[opcode_name]
		
		return super(Message, cls).__new__(cls)
	
	def __init__(self, opcode, client, server, data):
		self.opcode = opcode
		self.client = client
		self.server = server
		self.data = data

	def data_stream(self):
		return StringIO(self.data)
	
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

class SMSG_NAME_QUERY_RESPONSE(ServerMessage):
	@property
	def guid(self):
		return GUID(readGUID(self.data_stream()))
	
	@property
	def name(self):
		stream = self.data_stream()
		readGUID(stream)
		stream.read(1)
		
		return readstring(stream, encoding="utf-8")
	
	def __repr__(self):
		return "<%s: %s = %r>" % (self.__class__.__name__, self.guid, self.name)

class SMSG_QUERY_TIME_RESPONSE(ServerMessage):
	# Incomplete
	
	@property
	def timestamp(self):
		return unpack_from("<L", self.data)[0]
	
	@property
	def datetime(self):
		return datetime.fromtimestamp(self.timestamp)
	
	def __repr__(self):
		return "<%s: %s>" % (self.__class__.__name__, self.datetime)
