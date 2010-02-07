#!/usr/bin/python
# -*- coding: utf-8 -*-

"""Simple example script that dumps all encountered player names inside a logfile."""

import os
os.environ['DJANGO_SETTINGS_MODULE'] = "sigrie.settings"
from sigrie.owdb.models import Spell

from log import *
from cStringIO import StringIO
from struct import pack, unpack
from utils import *

import sys
from datetime import timedelta
import opcodes

sys.argv.pop(0)

DURATIONS_DEFAULT = {
	"second":  "second",
	"seconds": "seconds",
	"minute":  "minute",
	"minutes": "minutes",
	"hour":    "hour",
	"hours":   "hours",
	"day":     "day",
	"days":    "days",
}
def duration(value, locales=DURATIONS_DEFAULT):
	if not isinstance(value, timedelta):
		if value < 0: value = 0
		value = timedelta(milliseconds=value)
	if value == timedelta(seconds=1):
		return "1 %s" % (locales["second"])
	elif value < timedelta(minutes=1):
		return "%g %s" % (value.seconds+float(value.microseconds)/1000000, locales["seconds"])
	elif value < timedelta(hours=1):
		return "%g %s" % (value.seconds / 60, value.seconds >= 120 and locales["minutes"] or locales["minute"])
	elif value <= timedelta(days=1):
		return "%g %s" % (value.seconds / 3600, value.seconds >= 7200 and locales["hours"] or locales["hour"])
	else:
		return "%g %s" % (value.days, value.days > 1 and locales["days"] or locales["day"])


class OPCode(object):
	def __init__(self, data):
		self.data = data

class CMSG_ITEM_QUERY_SINGLE(OPCode):
	def event(self):
		id = unpack("i", self.data)[0]
		print "Player queried item #%i" % (id)

class SMSG_ITEM_QUERY_SINGLE_RESPONSE(OPCode):
	def event(self):
		id = unpack("i", self.data[:4])[0]
		print "Server answered to query for item #%i" % (id)

class SMSG_MOTD(OPCode):
	def event(self):
		motd = self.data[4:].replace("\x00", "\n")
		print motd

class SMSG_PLAYED_TIME(OPCode):
	def event(self):
		played_total, played_this_level, _ = unpack("iic", self.data)
		played_total = duration(timedelta(seconds=played_total))
		played_this_level = duration(timedelta(seconds=played_this_level))
		print "Total time played: %s (%s this level)" % (played_total, played_this_level)

class SMSG_STANDSTATE_UPDATE(OPCode):
	def event(self):
		#print self.data == "\x01" and "Player sat down" or "Player stood up"
		pass

class SMSG_TRAINER_LIST(OPCode):
	def event(self):
		guid, _, chunks = unpack("<Qii", self.data[:16])
		print (guid >> 24) & 0xFFFFFF # id
		data = self.data[16:]
		for i in range(chunks):
			spell, trainable, cost, trainablePrimarySkill, firstPrimarySkill, level, required_skill, required_skill_level, required_spell1, required_spell2, _ = unpack("<i?iiibiiiii", data[:38])
			data = data[38:]
			spell = Spell.objects.get(id=spell)
			required_spell1 = required_spell1 and Spell.objects.get(id=required_spell1)
			required_spell2 = required_spell2 and Spell.objects.get(id=required_spell2)
		text = data[:data.find("\x00")]

for filename in sys.argv:
	if filename == "-":
		file = sys.stdin
	else:
		file = open(filename, "rb")
	
	for entry in Log(file):
		if isinstance(entry, Message):
			name = opcodes.names[entry.opcode]
			if name in globals():
				globals()[name](entry.data).event()
