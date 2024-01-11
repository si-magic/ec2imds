import datetime
from enum import Enum
import io
import json
import random
import re
import select
import socket
from time import sleep
from typing import Any, Callable
from urllib import error, request

from ec2imds.exceptions import *


class OurMagic:
	class EC(Enum):
		OK = 0
		GENERIC_ERR = 1
		USAGE_ERR = 2
	class Limits:
		MAX_IMDS_READ = 16384
		API_RETRY = 1
	class Timeout:
		EYEBALL = 1 # 1 s
		IMDS_TOKEN_TTL = datetime.timedelta(seconds = 21600)
	class Deltas:
		# Expire the token 30 seconds earlier
		IMDS_TOKEN_DELTA = datetime.timedelta(seconds = 30)
		IMDS_RETRY_DELAY = datetime.timedelta(milliseconds = 50)
	class RE:
		ALL = re.compile('''.*''')
		EP_FQDN = re.compile('''^((?:[a-z0-9\\-]+\\.?)+)(?::([0-9]+))?$''', re.I)
		EP_4 = re.compile('''^([0-9.]+)(?::([0-9]+))?$''', re.I)
		# Reserved interface index for future use. Python does not seem to
		# provide facilities for specifying source interface.
		EP_6 = re.compile('''^\\[([a-f0-9:]+(?:%[a-z0-9\\-_]+)?)\\](?::([0-9]+))?$''', re.I)
		DIRECTIVE = re.compile('''([a-z0-9\\/\\-_]+)(?:=(.*))?''', re.I)

'''
elastic-gpus and elastic-inference are intentionally left out.
'''
class IMDSAPIMagic:
	'''API magic values'''
	# default endpoint
	endpoints = [ ("169.254.169.254", None), ("fd00:ec2::254", None) ]
	# the latest version at the time of writing
	version = "latest"
	# tags can contain unicode characters encoded in UTF-8
	encoding = "utf-8"
	# text/plain response newline character
	nl = '\n'
	# path separator
	pathsep = '/'

# https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-categories.html
class IMDSCategory:
	def __init__ (self,
			path: str = None,
			func: Callable = None,
			arg: str = None):
		self.path = path
		self.func = func
		self.arg = arg

class IMDSLambda:
	def pt (x):
		'''Pass-through'''
		return x

	def ml2list (s: str) -> list[str]:
		'''Convert a multiline string to an array'''
		return s.split(IMDSAPIMagic.nl)

	def json (s):
		'''Load the arg as JSON data'''
		return json.loads(s)

class IMDSWrapper:
	'''IMDS v2 facility'''

	def construct_endpoint_str (t: tuple[str, int]) -> str:
		if ':' in t[0]:
			host = "[{addr}]".format(addr = t[0])
		else:
			host = t[0]
		if t[1] is None:
			return host
		return "{host}:{port}".format(host = host, port = str(t[1]))

	def mk_endpoint_from_str (s: str) -> tuple[str, int]:
		s = s.strip()
		for r in [ OurMagic.RE.EP_4, OurMagic.RE.EP_6, OurMagic.RE.EP_FQDN ]:
			m = r.match(s)
			if m:
				break
		if not m:
			raise ValueError("{v}: invalid format".format(v = s))

		host = m[1]
		if m[2]:
			port = int(m[2])
		else:
			port = None
		return ( host, port )

	def construct_endpoint_list_str (l: list[tuple[str, int]]) -> str:
		return ",".join([ IMDSWrapper.construct_endpoint_str(t) for t in l ])

	def mk_endpoint_list_from_str (s: str) -> list[tuple[str, int]]:
		l = s.split(',')
		return [ IMDSWrapper.mk_endpoint_from_str(ep) for ep in l ]

	def _define_scalar_directive (self, path: str, tf: Callable[[str], Any] = None):
		c = IMDSCategory(path, lambda *args: self.load_scalar(path, tf))
		self.dir_dict[path] = c

	def _define_list_directive (self, path: str):
		c = IMDSCategory(path, lambda *args: self.load_scalar(path, IMDSLambda.ml2list))
		self.dir_dict[path] = c

	def _define_json_directive (self, path: str):
		c = IMDSCategory(path, lambda *args: self.load_scalar(path, IMDSLambda.json))
		self.dir_dict[path] = c

	def _define_tree_directive (
			self,
			path: str,
			depth: int,
			type_f: list[tuple[re.Pattern, Callable[[str], Any]]] = None):
		c = IMDSCategory(path, lambda *args: self.load_tree(path, depth, type_f))
		self.dir_dict[path] = c

	def _define_public_key_directive (self, path: str):
		def load_public_keys (*args):
			ret = {}
			scalar = self.load_scalar(path, IMDSLambda.ml2list)
			if not scalar:
				return

			for kn in scalar:
				sep = kn.find('=')
				if sep <= 0:
					idx = kn
					name = None
				else:
					idx = kn[:sep]
					name = kn[sep + 1:]
			ret[idx] = {
				"name": name,
				"keys": self.load_tree(path + IMDSAPIMagic.pathsep + idx, 1)
			}

			return ret

		c = IMDSCategory(path, load_public_keys)
		self.dir_dict[path] = c

	# https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Run_Instance_Idempotency.html
	def _try_urlopen (
			self,
			req,
			tries: int = None,
			delay: datetime.timedelta = None):
		if tries is None:
			tries = self._tries
		if tries <= 0:
			raise ValueError("{v}: invalid tries value: ".format(v = str(tries)))
		if delay is None:
			delay = self._retry_delay

		saved_e = None
		for i in range(0, tries):
			try:
				return request.urlopen(req)
			except error.HTTPError as e:
				saved_e = e
				if e.code / 100 != 5: raise e
				sleep(delay.total_seconds())

		self.reset_states() # find another endpoint next time
		raise saved_e

	def __init__ (
			self,
			endpoints: list[tuple[str, int]] = IMDSAPIMagic.endpoints,
			token_ttl: datetime.timedelta = OurMagic.Timeout.IMDS_TOKEN_TTL,
			tries: int = OurMagic.Limits.API_RETRY,
			retry_delay: datetime.timedelta = OurMagic.Deltas.IMDS_RETRY_DELAY):
		self.dir_dict = dict[str, IMDSCategory]()
		self.on_new_token: Callable[[str, datetime.datetime, tuple[str, int]], Any] = None
		self.on_load_token: Callable[[tuple[str, int]], tuple[str, datetime.datetime] | None] = None

		self._rnd = random.Random()
		self._token: str = None
		self._token_expiry: datetime.datetime = None
		self._endpoints = endpoints
		self._token_ttl = token_ttl
		self._current: tuple[str, int] = None
		self._tries = tries
		self._retry_delay = retry_delay

		self.expire_token()

		self._define_scalar_directive("meta-data/ami-id")
		self._define_scalar_directive("meta-data/ami-launch-index", int)
		self._define_scalar_directive("meta-data/ami-manifest-path")
		self._define_list_directive("meta-data/ancestor-ami-ids")
		self._define_scalar_directive(
			"meta-data/autoscaling/target-lifecycle-state")
		self._define_tree_directive(
			"meta-data/block-device-mapping",
			1)
		self._define_json_directive("meta-data/events/maintenance/history")
		self._define_json_directive("meta-data/events/maintenance/scheduled")
		self._define_json_directive("meta-data/events/recommendations/rebalance")
		self._define_scalar_directive("meta-data/hostname")
		self._define_json_directive("meta-data/iam/info")
		self._define_tree_directive(
			"meta-data/iam/security-credentials",
			1,
			[ ( OurMagic.RE.ALL, IMDSLambda.json ) ])
		self._define_json_directive("meta-data/identity-credentials/ec2/info")
		self._define_json_directive("meta-data/identity-credentials/ec2/security-credentials/ec2-instance")
		self._define_scalar_directive("meta-data/instance-action")
		self._define_scalar_directive("meta-data/instance-id")
		self._define_scalar_directive("meta-data/instance-life-cycle")
		self._define_scalar_directive("meta-data/instance-type")
		self._define_scalar_directive("meta-data/ipv6")
		self._define_scalar_directive("meta-data/kernel-id")
		self._define_scalar_directive("meta-data/local-hostname")
		self._define_scalar_directive("meta-data/local-ipv4")
		self._define_scalar_directive("meta-data/mac")
		self._define_tree_directive(
			"meta-data/network/interfaces/macs",
			3,
			[
				# index
				( re.compile('''meta-data\\/network\\/interfaces\\/macs\\/(?:(?:[a-fA-F0-9]{2}:)){5}[a-fA-F0-9]{2}\\/(device-number|network-card-index)'''), int ),
				# multiline values
				( re.compile('''meta-data\\/network\\/interfaces\\/macs\\/(?:(?:[a-fA-F0-9]{2}:)){5}[a-fA-F0-9]{2}\\/(ipv4-associations\\/public-ip|ipv6s|local-ipv4s|public-ipv4s|security-groups|security-group-ids|subnet-ipv6-cidr-blocks|vpc-ipv4-cidr-blocks|vpc-ipv6-cidr-blocks)'''), IMDSLambda.ml2list )
			])
		self._define_scalar_directive("meta-data/placement/availability-zone")
		self._define_scalar_directive("meta-data/placement/availability-zone-id")
		self._define_scalar_directive("meta-data/placement/group-name")
		self._define_scalar_directive("meta-data/placement/host-id")
		self._define_scalar_directive("meta-data/placement/partition-number")
		self._define_scalar_directive("meta-data/placement/region")
		self._define_list_directive("meta-data/product-codes")
		self._define_scalar_directive("meta-data/public-hostname")
		self._define_scalar_directive("meta-data/public-ipv4")
		# Undocumented category
		# Seems to return the type of virtualisation(pv or hvm).
		self._define_scalar_directive("meta-data/profile")
		self._define_public_key_directive("meta-data/public-keys")
		self._define_scalar_directive("meta-data/ramdisk-id")
		self._define_scalar_directive("meta-data/reservation-id")
		self._define_list_directive("meta-data/security-groups")
		self._define_scalar_directive("meta-data/services/domain")
		self._define_scalar_directive("meta-data/services/partition")
		self._define_json_directive("meta-data/spot/instance-action")
		self._define_tree_directive("meta-data/tags/instance", 1)
		self._define_scalar_directive("meta-data/fws/instance-monitoring")
		self._define_json_directive("meta-data/instance-identity/document")
		self._define_scalar_directive("meta-data/instance-identity/pkcs7")
		self._define_scalar_directive("meta-data/instance-identity/signature")
		# Undocumented category
		# Seems to return the type of hypervisor(Nitro or container)
		self._define_scalar_directive("meta-data/system")

	def _eyeball (self, service: str, protocol: str) -> tuple[str, int]:
		'''rfc8305'''
		socks = list[socket.socket]()
		ep_map = {}
		f_order = [ socket.AF_INET6, socket.AF_INET ]

		if protocol != "tcp":
			raise NotImplementedError("{v}: not implemented".format(v = protocol))
		port = socket.getservbyname(service, protocol)

		try:
			# do query and set up sockets
			for f in f_order:
				for h in self._endpoints:
					try:
						l = socket.getaddrinfo(
							h[0],
							h[1] if h[1] else port,
							f,
							socket.SOCK_STREAM,
							socket.IPPROTO_TCP)
						i = self._rnd.randrange(0, len(l))
						ep = l[i]
						s = socket.socket(ep[0], ep[1], ep[2])
						s.setblocking(False)

						try:
							s.connect(ep[4])
						except BlockingIOError:
							pass
						except:
							s.close()
							continue
						socks.append(s)
						ep_map[s] = h
					except socket.gaierror:
						pass
			# do select
			ready = select.select([], socks, [], OurMagic.Timeout.EYEBALL)[1]
			# select the best one
			if ready:
				ret = None
				for s in ready:
					en = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
					if en:
						continue

					if s.family == socket.AF_INET6:
						return ep_map[s]
					elif not ret:
						ret = ep_map[s]

				if ret:
					return ret
		finally:
			for s in socks:
				s.close()
		raise EyeballError("no endpoint could be reached")

	def token_expired (self) -> bool:
		return self._token_expiry < datetime.datetime.now(datetime.UTC)

	def expire_token (self):
		self._token_expiry = datetime.datetime.fromtimestamp(0, datetime.UTC)

	def _set_current (self, service: str = "http", protocol: str = "tcp"):
		if self._current: return
		self._current = self._eyeball(service, protocol)

	def _construct_url (self, rl: str, apiver: str = None) -> str:
		self._set_current()
		ep = IMDSWrapper.construct_endpoint_str(self._current)

		if apiver is None:
			apiver = IMDSAPIMagic.version

		return '''http://{ep}/{apiver}/{rl}'''.format(
			ep = ep,
			apiver = apiver,
			rl = rl)

	def reset_states (self):
		self.expire_token()
		self._token = None
		self._current = None

	def open_url (self, path: str, apiver: str = None) -> io.BufferedIOBase | None:
		# ensure that there's a token
		self.get_token()

		saved = None
		for i in range(0, 2):
			req = self.mk_request(loc = path, apiver = apiver)
			try:
				return self._try_urlopen(req)
			except error.HTTPError as e:
				saved = e
				match e.code:
					case 404:
						return
					case 401:
						'''Somehow the endpoint rejects the token. Probably the
						leftover token from the image is being used. Get a new
						token and try one more time.
						'''
						self.expire_token()
						self.get_token()
						continue
					case _:
						break
		raise saved

	def load_scalar (self, path: str, tf: Callable[[str], Any] = None):
		if tf is None:
			tf = IMDSLambda.pt
		req = self.open_url(path)
		if req: return tf(req
					.read(OurMagic.Limits.MAX_IMDS_READ)
					.decode(IMDSAPIMagic.encoding))

	def load_tree (
			self,
			path: str,
			depth: int,
			type_f: list[tuple[re.Pattern, Callable[[str], Any]]] = None) -> dict:
		if depth < 0:
			raise RecursionError(path)
		if type_f is None:
			type_f = []

		scalars = self.load_scalar(path, IMDSLambda.ml2list)
		if scalars is None:
			return

		ret = {}
		for s in scalars:
			if s.endswith(IMDSAPIMagic.pathsep):
				n = s[:-1]
				child = path + IMDSAPIMagic.pathsep + n
				v = self.load_tree(child, depth - 1, type_f)
			else:
				child = path + IMDSAPIMagic.pathsep + s
				n = s
				tf = None
				for r, f in type_f:
					if r.match(child):
						tf = f
						break
				v = self.load_scalar(child, tf)
			ret[n] = v

		return ret

	def open_userdata (self) -> io.BufferedIOBase:
		return self.open_url("user-data")

	def get_token (self) -> tuple[str, datetime.datetime, tuple[str, int]]:
		if not self._token and self.on_load_token:
			self._set_current()
			t = self.on_load_token(self._current)
			if t:
				self._token = t[0]
				self._token_expiry = t[1]

		if not self.token_expired() and self._token and self._current:
			# all good
			return (self._token, self._token_expiry, self._current)

		self._token = None
		# let's go get it
		req_sent = datetime.datetime.now(datetime.UTC)
		req = self.mk_request(
			loc = "api/token",
			apiver = "latest", # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html#imds-considerations
			method = "PUT",
			headers = {
				"X-aws-ec2-metadata-token-ttl-seconds":
					int(self._token_ttl.total_seconds())})
		with self._try_urlopen(req) as f:
			self._token = (f
				  .read(OurMagic.Limits.MAX_IMDS_READ)
				  .decode(IMDSAPIMagic.encoding))
			self._token_expiry = (
				req_sent + self._token_ttl - OurMagic.Deltas.IMDS_TOKEN_DELTA)

		if self.on_new_token:
			self.on_new_token(self._token, self._token_expiry, self._current)
		return ( self._token, self._token_expiry, self._current )

	def mk_request (
			self,
			loc: str,
			apiver: str = None,
			data = None,
			method: str = None,
			headers: dict = {}):
		if self._token: headers["X-aws-ec2-metadata-token"] = self._token
		return request.Request(
			url = self._construct_url(loc, apiver),
			data = data,
			headers = headers,
			method = method)

	def all (self, args = None) -> dict[str, Any]:
		ret = dict[str, Any]()

		for k, d in self.dir_dict.items():
			ret[k] = d.func(args)

		return ret

ver = "0.0.3"
rev = 0
imds_ver = IMDSAPIMagic.version
