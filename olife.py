import ssl
import hmac
import hashlib
import glob
import json
import os
from socket import *
from select import epoll, EPOLLIN, EPOLLHUP

import logging
from systemd.journal import JournalHandler

# Custom adapter to pre-pend the 'origin' key.
# TODO: Should probably use filters: https://docs.python.org/3/howto/logging-cookbook.html#using-filters-to-impart-contextual-information
class CustomAdapter(logging.LoggerAdapter):
	def process(self, msg, kwargs):
		return '[{}] {}'.format(self.extra['origin'], msg), kwargs

logger = logging.getLogger() # __name__
journald_handler = JournalHandler()
journald_handler.setFormatter(logging.Formatter('[{levelname}] {message}', style='{'))
logger.addHandler(journald_handler)
logger.setLevel(logging.DEBUG)

class LOG_LEVELS:
	CRITICAL = 1
	ERROR = 2
	WARNING = 3
	INFO = 4
	DEBUG = 5

def log(*msg, origin='UNKNOWN', level=5, **kwargs):
	if level <= LOG_LEVEL:
		msg = [item.decode('UTF-8', errors='backslashreplace') if type(item) == bytes else item for item in msg]
		msg = [str(item) if type(item) != str else item for item in msg]
		log_adapter = CustomAdapter(logger, {'origin': origin})
		if level <= 1:
			log_adapter.critical(' '.join(msg))
		elif level <= 2:
			log_adapter.error(' '.join(msg))
		elif level <= 3:
			log_adapter.warning(' '.join(msg))
		elif level <= 4:
			log_adapter.info(' '.join(msg))
		else:
			log_adapter.debug(' '.join(msg))

def drop_privileges():
	return True

class obtain_life():
	def __init__(self, secret, alg='HS256', host='obtain.life', port=1339, cert=None, key=None):
		self.sock = socket()
		self.sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
		self.sock.connect((host, port))
		self.pollobj = epoll()

		if not cert:
			for file in glob.glob('*.pem'):
				with open(file, 'r') as fh:
					if 'BEGIN CERTIFICATE' in fh.readline():
						cert = file
						break
		if not key:
			for file in glob.glob('*.pem'):
				with open(file, 'r') as fh:
					line = fh.readline()
					if 'BEGIN' in line and 'PRIVATE KEY' in line:
						key = file
						break

		#context = ssl.create_default_context()
		#context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
		#context.load_cert_chain(cert, key)

		context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
		context.load_default_certs()

		self.sock = context.wrap_socket(self.sock, server_side=False, server_hostname=host, do_handshake_on_connect=True)
		self.pollobj.register(self.sock.fileno(), EPOLLIN)

		while drop_privileges() is None:
			log('Waiting for privileges to drop.', once=True, level=5, origin='slimHTTP', function='http_serve')

		self.main_so_id = self.sock.fileno()

		self.host = host
		self.secret = secret
		self.alg = alg

		self.domain = None # Has to subscribe to one first.
		self.authenticated = {}
		self.user_cache = {}

	def HMAC_256(self, data, key=None):
		if not key: key = self.secret
		if type(data) == dict: data = json.dumps(data, separators=(',', ':'))
		log(f'Signing with key: {key}', origin='obtain_life.HMAC_256', level=LOG_LEVELS.DEBUG)
		log(json.dumps(json.loads(data), indent=4, separators=(',', ':')), origin='obtain_life.HMAC_256', level=LOG_LEVELS.DEBUG)

		signature = hmac.new(bytes(key , 'UTF-8'), msg=bytes(data , 'UTF-8'), digestmod = hashlib.sha256).hexdigest().upper()
		return signature

	def poll(self, timeout=0.001, *args, **kwargs):
		return dict(self.pollobj.poll(timeout))

	def close(self, *args, **kwargs):
		self.pollobj.unregister(self.main_so_id)
		self.sock.close()

	def send(self, data):
		if type(data) == dict: data = json.dumps(data)
		if type(data) != bytes: data = bytes(data, 'UTF-8')

		self.sock.send(data)

	def recv(self, buf=8192, *args, **kwargs):
		if self.poll(*args, **kwargs):
			return self.sock.recv(buf)
		return True

	def parse(self, data):
		if type(data) is bytes and len(data) <= 0:
			log('Life disconnected on us, reconnect?', origin='obtain_life.parse', level=LOG_LEVELS.WARNING)
			self.close() # reconnect?
			return None

		if type(data) == bool: return None

		if type(data) != dict: data = json.loads(data.decode('UTF-8'))
		
		log(f'Life sent: {data}', origin='obtain_life.parse', level=LOG_LEVELS.DEBUG)
		if '_module' in data:
			if data['_module'] == 'auth':
				## Someone logged in
				user = data['user']
				token = data['token']

				packet_signature = data['sign']
				del(data['sign'])
				my_signature = life.HMAC_256(data)
				if not packet_signature == my_signature:

					log(f'Invalid signature from identity manager, expected signature: {my_signature} but got {packet_signature}.', origin='parse_life', level=LOG_LEVELS.CRITICAL)
					return None

				if not user['domain'] in self.user_cache: self.user_cache[user['domain']] = {}
				self.user_cache[user['domain']][user['username']] = token
				self.authenticated[token] = user

				log(f'User {user["username"]}@{user["domain"]} logged in', level=LOG_LEVELS.INFO, origin='parse_life')

		return data

	def subscribe(self, domain, secret):
		payload = {
			"alg": "HS256",
			"domain": domain,
			"_module": "register",
			"service": "backend"
		}
		## Add the service signature, and then the JWT signature.
		payload['service_sign'] = self.HMAC_256(payload, secret)
		payload['sign'] = self.HMAC_256(payload, self.secret)

		self.domain = domain

		self.send(payload)

	def is_loggedin(self, token, domain=None):
		if not domain: domain = self.domain
		if token in self.authenticated: return True
		elif domain and domain in self.user_cache and token in self.user_cache[domain]: return True
		return False

	def login(self, user, password):
		payload = {
			"alg": self.alg,
			"domain": self.domain,
			"_module": "auth",
			"username": user,
			"password": password
		}
		payload['sign'] = self.HMAC_256(payload, self.secret)

		self.send(payload)