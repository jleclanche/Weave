#!/usr/bin/python
# -*- coding: utf-8 -*-
from weave import events

class MyHandler(events.Handler):
	"""
	A basic handler subclass
	"""
	def CMSG_MONSTER_MOVE(msg):
		print "A monster has moved! %r" % (msg)
	
	def CMSG_AUTH_SESSION(msg):
		print "New session, %r" % (msg)

# Attach to Weave
events.attach(MyHandler())
