#!/usr/bin/env python3
import socket
import selectors
import pickle
import struct
import os
import lzma
from decimal import Decimal, getcontext
from passwd import Passwd

appprefix = 'atop'
hosts = {
	'127.0.0.1': {
		'prefix': ('servers', 'vps1'),
		'passwd': Passwd('/etc/passwd')
	}
}
listenaddr = ('127.0.0.1', 61000)
graphiteaddr = ('127.0.0.1', 2004)
parsers = {}

def debug(func):
	def wrapper(*args, **kwargs):
		print('DEBUG: fn {} args {} kwargs {}'.format(func.__name__, args, kwargs.items()))
		return func(*args, **kwargs)
	return wrapper

class ClientHandler:
	hostcfg = None
	sock = None
	data = None
	state = None
	lzmaobj = None

	def __init__(self, sock, hostcfg):
		self.lzmaobj = lzma.LZMADecompressor()
		self.sock = sock
		self.hostcfg = hostcfg
		self.reset()

	def reset(self):
		self.data = ''
		self.state = {'ignore': False, 'metrics': [], 'processes': {'epoch': 0, 'owners': {}, 'total': 0, 'active': 0}, 'users': {}}

	def eof(self):
		sel.unregister(self.sock)
		self.sock.close()

	def read(self):
		print('ping')
		data = self.sock.recv(4096)
		if not data:
			self.eof()
		else:
			self.data += self.lzmaobj.decompress(data).decode()
			for line, self.data in parselines(self.data):
				self.parse(line)

	def addprocess(self, epoch, pid, userid, state):
		self.state['processes']['epoch'] = epoch
		self.state['processes']['owners'][pid] = userid
		self.state['processes']['total'] += 1
		if state in ("D", "R"):
			self.state['processes']['active'] += 1

	def addprocessmetric(self, epoch, pid, metric, value):
		userid = self.state['processes']['owners'][pid]
		if userid not in self.state['users']:
			self.state['users'][userid] = {}
		if metric not in self.state['users'][userid]:
			self.state['users'][userid][metric] = {}
		if epoch not in self.state['users'][userid][metric]:
			self.state['users'][userid][metric][epoch] = 0
		self.state['users'][userid][metric][epoch] += value

	def parse(self, line):
		command, sep, line = line.partition(' ')
		if command in parsers:
			parsers[command](self, command, line)

	def push(self, epoch, metric, value):
		valuetup = epoch, str(value)
		prefix = (appprefix,) + self.hostcfg['prefix'] + metric
		data = '.'.join(prefix), valuetup
		self.state['metrics'].append(data)

	def flush(self, ignore):
		if len(self.state['users']):
			for userid, userinfo in self.state['users'].items():
				username = self.hostcfg['passwd'].getuser(userid)
				if not username:
					continue
				for metric, metricinfo in userinfo.items():
					for epoch, value in metricinfo.items():
						self.push(epoch, ('users', username) + metric, value)

		if self.state['processes']['total']:
			self.push(self.state['processes']['epoch'], ('processes', 'total'), self.state['processes']['total'])
			self.push(self.state['processes']['epoch'], ('processes', 'active'), self.state['processes']['active'])

		if len(self.state['metrics']):
			print('->', self.state['metrics'])
			payload = pickle.dumps(self.state['metrics'], protocol=2)
			header = struct.pack("!L", len(payload))
			message = header + payload
			graphitesock.send(message)
		self.reset()
		self.state['ignore'] = ignore

def parselines(text):
	line, sep, text = text.partition('\n')
	while sep != '':
		yield line, text
		line, sep, text = text.partition('\n')
	raise StopIteration

def splitline(line, *args):
	words = line.split(' ', len(args))
	result = [cls(word) for cls, word in zip(args, words)]
	if len(result) < len(args):
		result.extend((len(args) - len(result))*[None])
	if len(words) > len(args):
		line = words[-1]
	else:
		line = ''
	return result, line

def parser(*cmds):
	def wrapper(func):
		for cmd in cmds:
			parsers[cmd] = func
		return func
	return wrapper

def infoparser(*cmds):
	def wrapper(func):
		def ignorecheck(clienthandler: ClientHandler, command, line):
			if not clienthandler.state['ignore']:
				(host, epoch, date, time, interval), line = splitline(line, str, int, str, str, int)
				for metric, value in func(command, interval, line):
					clienthandler.push(epoch, metric, value)
		for cmd in cmds:
			parsers[cmd] = ignorecheck
		return ignorecheck
	return wrapper

def parseparanthesis(text):
	if text[0] != '(':
		raise ValueError
	i = 1
	nesting = 1
	while nesting > 0:
		if text[i] == '(':
			nesting += 1
		elif text[i] == ')':
			nesting -= 1
		i += 1
	return text[0:i-1], text[i+1:]

def procparser(*cmds):
	def wrapper(func):
		def ignorecheck(clienthandler: ClientHandler, command, line):
			if not clienthandler.state['ignore']:
				(host, epoch, date, time, interval, pid), line = splitline(line, str, int, str, str, int, int)
				procname, line = parseparanthesis(line)
				state, line = splitline(line, str)
				for metric, value in func(command, pid, interval, line):
					clienthandler.addprocessmetric(epoch, pid, metric, value)
		for cmd in cmds:
			parsers[cmd] = ignorecheck
		return ignorecheck
	return wrapper

def hostconfig(ip):
	if ip not in hosts:
		return None
	return hosts[ip]

def doaccept():
	clientsock, addr = serversock.accept()
	ip, port = addr
	cfg = hostconfig(ip)
	if not cfg:
		print("Incoming connection from {}:{} rejected".format(ip, port))
		return
	print("New connection from {} aka {}".format(addr, cfg['prefix']))
	clientsock.setblocking(False)
	clienthandler = ClientHandler(clientsock, cfg)
	sel.register(clientsock, selectors.EVENT_READ, clienthandler.read)

@parser('RESET')
def parsereset(clienthandler, command, line):
	clienthandler.flush(True)

@parser('SEP')
def parsereset(clienthandler, command, line):
	clienthandler.flush(False)

@parser('PRG')
def parseprg(clienthandler, command, line):
	#PRG hetz 1495847188 2017/05/27 03:06:28 1 15111 (reader#4) S 0 0 15097 1 0 1495676278 () 1 0 1 0 0 0 0 0 0 0 0 n 0 0
	if clienthandler.state['ignore']:
		return
	(host, epoch, date, time, interval, pid), line = splitline(line, str, int, str, str, int, int)
	procname, line = parseparanthesis(line)
	(state, userid), line = splitline(line, str, int)
	clienthandler.addprocess(epoch, pid, userid, state)

def cpupercent(interval, tps, ticks):
	return round(100.0*ticks/(tps*interval),3)

@infoparser('cpu')
def parsecpu(command, interval, line):
	#CPU hetz 1495833790 2017/05/26 23:23:10 2 | 100 8 11 12 0 1572 5 0 0 0 0 16673 427
	#cpu hetz 1495833790 2017/05/26 23:23:10 2 | 100 0 2 0 0 197 0 0 0 0 0 1684 43
	(tps, cpuid, tsys, tuser, tuserniced, tidle, twait, tirq, tsoftirq, tsteal, tguest, freq, freqpercent), line = splitline(line, *(13*(int,)))
	result = []
	prefix = 'cpu-{}'.format(cpuid)
	for metric, value in {'system': tsys, 'user': tuser+tuserniced, 'wait': twait, 'irq': tirq+tsoftirq, 'idle': tidle}.items():
		result.append(((prefix, 'usage', metric), cpupercent(interval, tps, value)))
	if tguest:
		result.append(((prefix, 'usage', 'virt'), cpupercent(interval, tps, tguest+tsteal)))
	if freqpercent:
		for metric, value in {'absolute': freq, 'percent': freqpercent}.items():
			result.append(((prefix, 'frequency', metric), value))
	return result

@infoparser('CPL')
def parsecpl(command, interval, line):
	#CPL hetz 1495910632 2017/05/27 20:43:52 4075896 | 8 0.15 0.20 0.23 15712079978 8148709675
	(cpus, min1, min5, min15, contextswitches, interrupts), line = splitline(line, int, float, float, float, int, int)
	return [(('load', 'short'), min1), (('load', 'medium'), min5), (('load', 'long'), min15), (('contextswitches',), contextswitches), (('interrupts',), interrupts)]

@infoparser('MEM')
def parsemem(command, interval, line):
	#MEM hetz 1495910877 2017/05/27 20:47:57 1 | 4096 4029772 68775 1252235 53469 74436 22133 34810 0 12176 0 69 2097152 4096 3386
	(pgsize, size, free, pgcache, bufcache, slab, dirty), line = splitline(line, *(7*(int,)))
	result = []
	for metric, value in {'free': free, 'cached': pgcache+bufcache+slab, 'total': size}.items():
		result.append((('mem', metric), value*pgsize))
	return result

@infoparser('SWP')
def parseswp(command, interval, line):
	#SWP hetz 1495916702 2017/05/27 16:25:02 1 | 4096 2005999 1051759 0 5047403 3006151
	(pgsize, size, free, _, commitsize, commitlimit), line = splitline(line, *(6*(int,)))
	return [(('swap', 'total'), size*pgsize), (('swap', 'free'), free*pgsize), (('swap', 'commit'), commitsize*pgsize), (('swap', 'limit'), commitlimit*pgsize)]

@infoparser('PAG')
def parsepag(command, interval, line):
	#PAG hetz 1495916702 2017/05/27 16:25:02 1 4096 0 0 0 0 0
	(pgsize, scans, stalls, _, swapin, swapout), line = splitline(line, *(6*(int,)))
	return [(('swap', 'swapin'), swapin*pgsize), (('swap', 'swapout'), swapout*pgsize)]

@infoparser('LVM', 'MDD', 'DSK')
def parsedsk(command, interval, line):
	#DSK hetz 1495925455 2017/05/27 18:50:55 10802176 | vda 51667056 21147466 317105426 297519926 10095931632
	(name, ioms, readcount, readsectors, writecount, writesectors), line = splitline(line, str, int, int, int, int, int)
	return [(('disk', name, 'iosecs'), ioms/1000), (('disk', name, 'read'), readsectors), (('disk', name, 'write'), writesectors)]

@infoparser('NET')
def parsenet(command, interval, line):
	#NET hetz 1495926604 2017/05/27 19:10:04 10 lo 184 46039 184 46039 0 0
	#NET hetz 1495928073 2017/05/28 01:34:33 10 upper 7162 21748 6 14 7169 21758 7168 0
	(iface,), line = splitline(line, str)
	if iface == 'upper':
		(tcpin, tcpout, udpin, udpout), line = splitline(line, int, int, int, int)
		return [(('net', 'total', 'tcp', 'in'), tcpin), (('net', 'total', 'tcp', 'out'), tcpout), (('net', 'total', 'udp', 'in'), udpin), (('net', 'total', 'udp', 'out'), udpout)]
	else:
		(packetsin, bytesin, packetsout, bytesout), line = splitline(line, int, int, int, int)
		return [(('net', iface, 'packets', 'in'), packetsin), (('net', iface, 'bytes', 'in'), bytesin), (('net', iface, 'packets', 'out'), packetsout), (('net', iface, 'bytes', 'out'), bytesout)]

@procparser('PRC')
def parseprc(command, pid, interval, line):
	#PRC hetz 1495846440 2017/05/27 02:54:00 1 570 (atopacctd) S | 100 0 0 -20 100 0 0 6 0 570 y
	(tps, user, system), line = splitline(line, int, int, int)
	return [(('cpu', 'user'), cpupercent(tps, interval, user)), (('cpu', 'system'), cpupercent(tps, interval, system))]

@procparser('PRM')
def parseprm(command, pid, interval, line):
	#PRM hetz 1495909416 2017/05/27 20:23:36 2 3438 (dockerd) S | 4096 919028 33352 39532 0 0 0 0 6304 247268 136 12752 1220 n 0
	(pgsize, vsz, res), line = splitline(line, int, int, int)
	return [(('mem', 'virt'), vsz*pgsize), (('mem', 'res'), res*pgsize)]

@procparser('PRD')
def parseprd(command, pid, interval, line):
	#PRD hetz 1495909981 2017/05/27 14:33:01 10786702 32287 (eggdrop) S | n y 2139488 2139488 253448 253448 121560
	(patch, std, readcount, readsectors, writecount, writesectors, writecancel), line = splitline(line, str, str, *(5*(int,)))
	if std == 'n':
		return []
	return [(('disk', 'read'), readsectors), (('disk', 'write'), writesectors)]

def mainloop():
	for key, mask in sel.select(60):
		key.data()

if __name__ == '__main__':
	sel = selectors.DefaultSelector()
	serversock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	serversock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	serversock.bind(listenaddr)
	serversock.listen(5)
	serversock.setblocking(False)
	sel.register(serversock, selectors.EVENT_READ, doaccept)
	graphitesock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	graphitesock.connect(graphiteaddr)
	Passwd.register(sel)
	keys = parsers.keys() - ['RESET', 'SEP', 'PRG']
	print('Listening on {} for -aPPRG,{}'.format(listenaddr, ','.join(keys)))
	while True:
		mainloop()
