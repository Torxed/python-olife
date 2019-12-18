import hmac
import hashlib
import glob
from socket import *
from select import epoll, EPOLLIN, EPOLLHUP
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
		context = context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
		context.load_verify_locations("ca.crt")
		try:
			self.sock = context.wrap_socket(self.sock, server_side=False, server_hostname=host, do_handshake_on_connect=True)
		except ssl.SSLCertVerificationError:
			pass
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
		print(f'Signing with key: {key}')
		print(json.dumps(json.loads(data), indent=4, separators=(',', ':')))

		signature = hmac.new(bytes(key , 'UTF-8'), msg=bytes(data , 'UTF-8'), digestmod = hashlib.sha256).hexdigest().upper()
		return signature

	def poll(self, timeout=0.001):
		return dict(self.pollobj.poll(timeout))

	def close(self, *args, **kwargs):
		self.pollobj.unregister(self.main_so_id)
		self.sock.close()

	def send(self, data):
		if type(data) == dict: data = json.dumps(data)
		if type(data) != bytes: data = bytes(data, 'UTF-8')

		self.sock.send(data)

	def recv(self, buf=8192):
		if self.poll():
			return self.sock.recv(buf)

	def parse_life_data(self, data):
		if not data or len(data) <= 0:
			log('Life disconnected on us, reconnect?', origin='olife.parse_life_data', level=LOG_LEVELS.WARNING)
			self.close() # reconnect?
			return None

		if type(data) != dict: data = json.loads(data.decode('UTF-8'))
		
		print('Life sent:', data)
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

				print(json.dumps(self.authenticated, indent=4))

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

	def is_loggedin(self, token, domain=''):
		if token in self.authenticated: return True
		elif self.domain and self.domain in self.user_cache and token in self.user_cache[self.domain]: return True
		return False