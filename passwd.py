from fcntl import ioctl
from termios import FIONREAD
from inotify_simple import INotify, flags, parse_events
import ctypes
import selectors
import os

class Passwd:
	inotify = None
	handlers = {}

	@classmethod
	def processevent(cls):
		# Available data
		bytes_avail = ctypes.c_int()
		ioctl(cls.inotify.fd, FIONREAD, bytes_avail)
		buffer_size = bytes_avail.value
		# Reading and parsing
		data = os.read(cls.inotify.fd, buffer_size)
		events = parse_events(data)
		for wd, mask, cookie, name in events:
			handler = cls.handlers[wd]
			if mask & flags.DELETE_SELF:
				handler.handle_delete()
			elif mask & flags.MODIFY:
				handler.handle_modify()

	@classmethod
	def register(cls, sel):
		sel.register(cls.inotify.fd, selectors.EVENT_READ, cls.processevent)

	def __init__(self, path):
		if not Passwd.inotify:
			Passwd.inotify = INotify()
		self.path = path
		self.handle_modify()
		self.add_watch()

	def add_watch(self):
		wd = Passwd.inotify.add_watch(self.path, flags.DELETE_SELF | flags.MODIFY)
		Passwd.handlers[wd] = self

	def handle_delete(self):
		self.add_watch()
		self.handle_modify()

	def handle_modify(self):
		self.users = {}
		with open(self.path, 'r') as f:
			for line in f:
				user, x, uid, line = line.split(':', 3)
				self.users[int(uid)] = user
		print('{} users read from {}'.format(len(self.users), self.path))
	
	def getuser(self, uid):
		if uid not in self.users:
			return None
		return self.users[uid]
