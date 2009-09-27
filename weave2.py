#!/usr/bin/python
#encoding: utf-8

PORT = 3724

from binascii import hexlify, unhexlify
from datetime import datetime
from operator import attrgetter
from weakref import ref
from struct import Struct, pack, unpack, unpack_from

from hashlib import sha1
from Crypto.Cipher import ARC4

from signal import SIGSTOP, SIGCONT
from ptrace.debugger.debugger import PtraceDebugger

import nids
import hmac
import os

import opcodes

def findKey(process, A, searchBlockSize=65536):
	"""Given the public value of A, find the session key K in memory.
	
	searchBlockSize is the amount of data to be read from memory at once."""
	
	process.kill(SIGSTOP)
	process.waitSignals()
	
	try:
		for mapping in process.readMappings():
			if mapping.pathname and mapping.pathname.startswith('/'):
				continue
			
			for i in xrange(mapping.start, mapping.end, searchBlockSize - 32):
				r = process.readBytes(i, searchBlockSize)
				findOffset = r.find(A)

				if findOffset >= 0:
					keyOffset = i + findOffset + 0x20
					K = process.readBytes(keyOffset, 40)
					return K
	finally:
		process.kill(SIGCONT)

def readstring(data, offset=0):
	"""Read a null-terminated string."""
	return data[offset:data.find(chr(0), offset)]

class Session(object):
	"""Stores information about a logged-in user, such as client information and session key."""
	def __init__(self, game, version, platform, os, locale, account):
		self.key = None
		self._game = game
		self._version = version
		self._platform = platform
		self._os = os
		self._locale = locale
		self._account = account
	
	game = property(attrgetter("_game"))
	version = property(attrgetter("_version"))
	platform = property(attrgetter("_platform"))
	os = property(attrgetter("_os"))
	locale = property(attrgetter("_locale"))
	account = property(attrgetter("_account"))
	
	def __str__(self):
		return "%s %d.%d.%d (Build %d) %s %s/%s %s" % ((self.game,) + self.version + (self.locale, self.os, self.platform, self.account))

class Message(object):
	"""Represents a single game message."""
	def __init__(self, source, opcode, data, date=None):
		self._source = source
		self._opcode = opcode
		self._data = data
		
		if date is None:
			date = datetime.now()
		self._date = date
	
	source = property(attrgetter("_source"))
	opcode = property(attrgetter("_opcode"))
	data = property(attrgetter("_data"))
	date = property(attrgetter("_date"))
	
	def __repr__(self):
		name = opcodes.names[self._opcode]
		
		if len(self._data) > 0:
			return "<%s: %d data bytes>" % (name, len(self._data))
		else:
			return "<%s>" % (name,)

class Peer(object):
	"""Base class for Client and Server."""
	def __init__(self, connection, address, halfstream):
		self._connection = ref(connection)
		self._address = address
		self._halfstream = halfstream
		self._halfstream.collect = 1
	
	@property
	def connection(self):
		return self._connection()
	
	address = property(attrgetter("_address"))
	
	def __del__(self):
		self._halfstream.collect = 0
	
	def __repr__(self):
		return "<%s %s:%d>" % ((self.__class__.__name__,) + self.address)

class BaseHeader(object):
	"""Base class for decoding client/server message headers."""
	length_struct = Struct(">H")
	
	def __init__(self, data):
		self._data = data[:self.size]

	def __repr__(self):
		return "<Header '%s': Length = %d, Opcode = 0x%X>" % (hexlify(self._data), self.content_length, self.opcode)
	
	@property
	def content_length(self):
		return self.length_struct.unpack_from(self._data)[0] - self.opcode_struct.size
	
	@property
	def opcode(self):
		return self.opcode_struct.unpack_from(self._data, self.length_struct.size)[0]

class Client(Peer):
	hmac_key = unhexlify("F4663159FC836E31310251D544316798")
	
	class Header(BaseHeader):
		size = 6
		opcode_struct = Struct("<L")

class Server(Peer):
	hmac_key = unhexlify("22BEE5CFBB0764D900451BD024B8D545")
	
	class Header(BaseHeader):
		size = 4
		opcode_struct = Struct("<H")

class Connection(object):
	"""Represents a TCP connection between two peers.
	
	This class is inherited by AuthConnection and RealmConnection
	and stores information such as the associated session.
	
	Upon discovering a new connection, an object of this type is
	instantiated. Once the first data has been processed, this
	class decides which kind of connection it is (auth or realm)
	and then 'specializes' by changing its type."""
	
	class InvalidDataException(ValueError):
		"""Raised when a packet is detected to contain bogus data."""
		pass
	
	def __init__(self, sniffer, tcp):
		self._sniffer = ref(sniffer)
		self.client = Client(self, tcp.addr[0], tcp.server)
		self.server = Server(self, tcp.addr[1], tcp.client)
	
	@property
	def sniffer(self):
		return self._sniffer()
	
	def handle_data(self, source, data):
		"""This function will only be called once and tries to determine
		whether this is a connection to the auth server or to a game
		server."""
		
		if source is self.client and len(data) >= AuthConnection.logon_challenge.size:
			# The first packet was sent by the client - this is most likely an
			# Auth Challenge, thus indicating the connection to an auth server.
			self.transform(AuthConnection)
			return self.handle_data(source, data)
		elif source is self.server:
			self.transform(RealmConnection)
			return self.handle_data(source, data)
	
	def transform(self, cls, *pargs):
		self.__class__ = cls
		cls.__transform_init__(self, *pargs)
	
	def __repr__(self):
		return "<%s between %r and %r>" % (self.__class__.__name__, self.client, self.server)

class AuthConnection(Connection):
	logon_challenge = Struct("<BH4s3BH4s4s4s2LB")
	
	def __transform_init__(self):
		self.session = None
	
	def handle_data(self, source, data):
		command, = unpack_from("<B", data)
		
		if command == 0: # Auth Challenge
			if source is self.client:
				err, size, game, major, minor, revision, build, platform, os, locale, tzoffset, ip, account_length = self.logon_challenge.unpack_from(data, 1)
				
				# The string fields are reversed
				game = game[::-1].strip(chr(0))
				platform = platform[::-1].strip(chr(0))
				os = os[::-1].strip(chr(0))
				locale = locale[::-1].strip(chr(0))
				
				account = unicode(data[self.logon_challenge.size+1:self.logon_challenge.size + 1 + account_length], "utf8")
				
				self.session = Session(game=game, version=(major, minor, revision, build), platform=platform, os=os, locale=locale, account=account)
				
				if self.sniffer:
					self.sniffer.sessions[account] = self.session
					self.sniffer.session_handler(self.session)
		
		elif source._halfstream.count == source._halfstream.count_new:
			# If this is the first data and it doesn't start with command 0, it's
			# invalid.
			raise Connection.InvalidDataException("Invalid opcode in first packet")
		
		if command == 1: # Auth Proof
			if source is self.client:
				# Note the SRP A value for later use
				self.session.A = data[1:33]
				# We can't read the key from memory here because the client
				# has not calculated it yet at this point.
			elif source is self.server and self.sniffer:
				for process in self.sniffer.processes.itervalues():
					# Try to find the key in any of the processes we're
					# attached to.
					key = findKey(process, self.session.A)
					
					if key:
						self.session.key = key
						break

class RealmConnection(Connection):
	def __transform_init__(self):
		self.session = None
		self.encrypted = False
		self.rc4 = { self.client: None, self.server: None }
		self.header = { self.client: None, self.server: None }
		self.buffer = { self.client: "", self.server: "" }
	
	def handle_data(self, source, data):
		# Append the received data to our cache
		self.buffer[source] += data
		
		while True:
			# Loop until there is no more data
			
			if self.header[source]:
				# There is a header waiting for more data
				header = self.header[source]
			else:
				# No header is pending; process the next one
				
				if len(self.buffer[source]) < source.Header.size:
					# Our buffer is too small to contain a header
					return
				
				header = source.Header(self.buffer[source])
				
				if self.encrypted:
					if self.rc4[source]:
						header._data = self.rc4[source].decrypt(header._data)
					else:
						# The connection is encrypted, but we don't have a key
						# to decrypt it. Nothing more to do here.
						return
				
				self.header[source] = header
				self.buffer[source] = self.buffer[source][source.Header.size:]
			
			if source._halfstream.count == source._halfstream.count_new:
				if (source is self.server and header.opcode != 0x1EC) or (source is self.client and header.opcode != 0x1ED):
					raise Connection.InvalidDataException("Invalid opcode in first packet")
			
			if len(self.buffer[source]) < header.content_length:
				# The header indicates a size greater than what we have in our buffer now.
				# Cancel here and wait for the next data that arrives.
				return
			
			content = self.buffer[source][:header.content_length]
			self.buffer[source] = self.buffer[source][header.content_length:]
			
			# Assemble a message and send it to our handler
			message = Message(source, header.opcode, content)
			self.handle_message(message)
			
			self.header[source] = None
	
	def handle_message(self, message):
		if message.opcode == 0x1ED: # CMSG_AUTH_SESSION
			# After a CMSG_AUTH_SESSION packet, all traffic is encrypted.
			self.encrypted = True
			
			# Fortunately, the auth session packet contains the account name, which allows us to identify
			# the session that is associated with this connection.
			account = unicode(readstring(message.data, 8), "utf8")
			
			if self.sniffer and account in self.sniffer.sessions:
				# We check whether we have recorded a session for this account name.
				self.session = self.sniffer.sessions[account]
				
				if self.session.key:
					# If we have a key, setup encryption.
					for peer in (self.client, self.server):
						self.rc4[peer] = ARC4.new(hmac.new(peer.hmac_key, self.session.key, sha1).digest())
						# To prevent leaking key bytes, Blizzard encrypts a few null bytes before encrypting
						# anything that is sent over the network.
						self.rc4[peer].decrypt(chr(0) * 1024)
		
		if self.sniffer:
			# Dispatch the message to our sniffer's message handler.
			self.sniffer.message_handler(message)

class Sniffer(object):
	def __init__(self, pid=None):
		self.sessions = {}
		self.connections = {}
		self.dbg = PtraceDebugger()
		self.processes = {}
	
	def __del__(self):
		for pid in dict(self.processes):
			self.deleteProcess(pid)
		self.dbg.quit()
	
	def tcp_handler(self, tcp):	
		if tcp.nids_state == nids.NIDS_JUST_EST and tcp.addr[1][1] == PORT:
			self.connections[tcp.addr] = Connection(self, tcp)
		elif tcp.nids_state == nids.NIDS_DATA:
			if tcp.addr not in self.connections:
				return
			
			connection = self.connections[tcp.addr]
			
			try:
				if tcp.client.count_new:
					connection.handle_data(connection.server, tcp.client.data[:tcp.client.count_new])
				if tcp.server.count_new:
					connection.handle_data(connection.client, tcp.server.data[:tcp.server.count_new])
			except Connection.InvalidDataException:
				del self.connections[tcp.addr]
		
		elif tcp.nids_state in (nids.NIDS_CLOSE, nids.NIDS_TIMEOUT, nids.NIDS_RESET):
			if tcp.addr in self.connections:
				del self.connections[tcp.addr]
	
	def message_handler(self, message):
		pass
	
	def session_handler(self, session):
		pass
	
	def addProcess(self, pid):
		self.processes[pid] = self.dbg.addProcess(pid, False)
		self.processes[pid].cont()
	
	def deleteProcess(self, pid):
		self.dbg.deleteProcess(pid)
		del self.processes[pid]

def findWowProcess():
	for entry in os.listdir("/proc"):
		if not entry.isdigit(): continue
		
		try:
			with open("/proc/%s/cmdline" % entry, "r") as cmdline_file:
				cmdline = cmdline_file.read().lower()
		except:
			continue
		
		if cmdline.startswith("wow.exe"):
			return int(entry)

def main():
	from optparse import OptionParser
	parser = OptionParser()
	
	parser.add_option("-d", "--device", dest="device", help="sniff on network device DEVICE", metavar="DEVICE")
	parser.add_option("-f", "--file", dest="file", help="use pcap logfile FILE", metavar="FILE")
	parser.add_option("-p", "--pid", dest="pid", help="attach to process PID", metavar="PID")
	
	(options, args) = parser.parse_args()
	
	nids.param("scan_num_hosts", 0) # Disable portscan detection
	
	sniff = Sniffer()
	sniff.starttime = datetime.now()
	
	def timestring():
		td = datetime.now() - sniff.starttime
		return "[% 8.3f]" % (td.seconds + td.microseconds/1000000.0)
	
	def message_output_handler(message):
		print timestring(), opcodes.names[message.opcode].ljust(55),
		
		if len(message.data) > 0:
			print "% 6d bytes" % len(message.data)
		else:
			print
	
	def session_output_handler(session):
		print timestring(), "New Session:", session
	
	sniff.message_handler = message_output_handler
	sniff.session_handler = session_output_handler
	
	if options.device:
		nids.param("device", options.device)
	if options.file:
		nids.param("filename", options.file)
	
	pid = None
	
	if options.pid is not None and options.pid.isdigit():
		pid = int(options.pid)
	elif options.pid == "auto":
		pid = findWowProcess()
	
	if pid:
		print timestring(), "Attaching to process", pid
		sniff.addProcess(pid)
	elif not options.file:
		print timestring(), "Warning: Not attaching to any process"
	
	nids.init()
	nids.register_tcp(sniff.tcp_handler)
	
	nids.run()

if __name__ == "__main__":
	main()