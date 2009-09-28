#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Weave events API
"""

class Stream(object):
	def __init__(self):
		self.handlers = []
	
	def attach(self, handle):
		self.handlers.append(handle)
	
	def fire(self, evt, msg):
		print self.handlers, "Do we even have any handler?"
		for handle in self.handlers:
			print handle, self.handlers
			handle.fire(evt, msg)

class Handler(object):
	def fire(self, evt, msg):
		print "IM FIRING MY LAZAH %r" % evt
		if hasattr(self, evt):
			getattr(self, evt)(msg)

stream = Stream()

def attach(handle):
	if not isinstance(handle, Handler):
		raise TypeError("Attaching a handle requires a Handler subclass, not %r" % (type(handle)))
	stream.attach(handle)
