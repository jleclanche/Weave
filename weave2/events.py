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
		for handle in self.handlers:
			handle.fire(evt, msg)

class Handler(object):
	def fire(self, evt, msg):
		if hasattr(self, evt):
			getattr(self, evt)(msg)

stream = Stream()

def attach(handle):
	if not isinstance(handle, Handler):
		raise TypeError("Attaching a handle requires a Handler subclass, not %r" % (type(handle)))
	stream.attach(handle)
