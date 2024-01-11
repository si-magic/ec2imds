import datetime
import getopt
import io
import json
import os
import re
import sys
from typing import Iterable

import ec2imds
from ec2imds import *


class UsageError (BaseException): ...
class TTYOutputError(BaseException): ...

class RunParam:
	def __init__ (self):
		home = os.getenv("HOME")

		self.cmds: set[str] = set[str]()
		self.arg: str = None

		self.directives: dict[str, str] = dict[str, str]()
		self.verbose: int = 0
		self.imds = IMDSAPIMagic.endpoints
		if home:
			self.t: str = home + "/.cache/ec2-imds/tokens"
		else:
			self.t: str = ""

def print_help (out: io.TextIOBase, program: str) -> int:
	defaults = RunParam()
	return out.write(
'''ec2imds, the extensive EC2 Instance Meta Data Service(IMDS) tool
Usage: ec2imds [options] <command> [directives]
Commands:
  --help, -h              print this message and exit
  -V, --version           print version info and exit
  -a, --all               get everything (default behaviour)
  -E <REGEX>              execute directives matching the pattern
  -L, --list-all          list all directives implemented
  -l <REGEX>              list directives matching the pattern
  -U, --user-data         output user-data to stdout(must not be a tty)
Options:
  -v, --verbose           increase verbosity level
  --imds=<ENDPOINT_LIST>  override the hardcoded IMDS endpoints
                          (default: {imds})
  -t <DIR>                override path to token directory
                          (default: {t})
'''.format(
	prog = program,
	imds = IMDSWrapper.construct_endpoint_list_str(defaults.imds),
	t = defaults.t))

def print_version (out: io.TextIOBase) -> int:
	return out.write("Version: {ver}{nl}Revision: {rev}{nl}IMDS version: {imds}"
				.format(
					ver = ec2imds.ver,
					rev = ec2imds.rev,
					imds = ec2imds.imds_ver,
					nl = os.linesep))

def init_from_opts (argv: list[str]) -> tuple[RunParam, IMDSWrapper]:
	rp = RunParam()

	opts, args = getopt.getopt(
		argv,
		"hVvaE:t:l:LU",
		[
			"help",
			"version",
			"verbose",
			"all",
			"imds=",
			"list-all",
			"user-data" ])
	for k, v in opts:
		match k:
			## commands
			case "--help" | "-h": rp.cmds.add("help")
			case "--version" | "-V": rp.cmds.add("version")
			case "--all" | "-a": rp.cmds.add("exec-all")
			case "-E":
				rp.cmds.add("exec")
				rp.arg = re.compile(v)
			case "--list-all" | "-L": rp.cmds.add("list-all")
			case "-l":
				rp.cmds.add("list")
				rp.arg = re.compile(v)
			case "--user-data" | "-U":
				rp.cmds.add("user-data")
			## options
			case "--verbose" | "-v": rp.verbose += 1
			case "--imds": rp.imds = IMDSWrapper.mk_endpoint_list_from_str(v)
			case "-t": rp.t = v

	w = IMDSWrapper(endpoints = rp.imds)
	dirs = w.dir_dict.keys()

	if not rp.cmds:
		if args:
			rp.cmds.add("exec")
		else:
			rp.cmds.add("exec-all")
	if len(rp.cmds) > 2 and "help" not in rp.cmds and "version" not in rp.cmds:
		raise UsageError("{v}: conflicting commands".format(",".join(rp.cmds)))

	# translate commands
	if "list-all" in rp.cmds:
		rp.cmds.add("list")
		rp.cmds.remove("list-all")
		rp.arg = OurMagic.RE.ALL
	elif "exec-all" in rp.cmds:
		rp.cmds.add("exec")
		rp.cmds.remove("exec-all")
		rp.arg = OurMagic.RE.ALL

	if rp.cmds.intersection([ "list", "exec" ]) and rp.arg:
		for k in w.dir_dict.keys():
			if rp.arg.match(k):
				rp.directives[k] = None

	if "user-data" not in rp.cmds:
		# directives
		for v in args:
			m = OurMagic.RE.DIRECTIVE.match(v)
			if m:
				d = str(m[1])
				a = str(m[2])
			else:
				raise UsageError("{v}: invalid directive format".format(v = v))
			if d not in dirs:
				raise UsageError("{v}: unknown directive".format(v = d))
			rp.directives[d] = a

	return (rp, w)

def perr (msg: str) -> int:
	return sys.stderr.write("{msg}{nl}".format(msg = msg, nl = os.linesep))

def cmd_list (it: Iterable[str]):
	for l in it:
		print(l)

def cmd_exec_dir (it: Iterable[tuple[str, str]]):
	obj = {}
	for k, v in it:
		obj[k] = w.dir_dict[k].func(v)

	json.dump(obj, sys.stdout, indent = '\t')
	print()

def cmd_user_data ():
	try:
		if sys.stdout.isatty():
			raise TTYOutputError("refusing to output to tty")
	except AttributeError:
		# Nothing we can do if the OS doesn't do isatty()
		pass

	with w.open_userdata() as stream:
		flag = bool(stream)
		while flag:
			flag = sys.stdout.buffer.write(stream.read(OurMagic.Limits.MAX_IMDS_READ)) > 0
	sys.stdout.buffer.flush()

def on_new_token (
		token: str,
		expiry: datetime.datetime,
		endpoint: tuple[str, int]):
	# save the new token
	doc = {
		"token": token,
		"expiry": expiry.isoformat()
	}

	fp = rp.t + os.path.sep + IMDSWrapper.construct_endpoint_str(endpoint)
	os.makedirs(rp.t, 0o700, True)

	saved_umask = os.umask(0o077)
	with open(fp, "w") as f:
		json.dump(doc, f)
	os.umask(saved_umask)

def on_load_token (endpoint: tuple[str, int]) -> tuple[str, datetime.datetime]:
	fp = rp.t + os.path.sep + IMDSWrapper.construct_endpoint_str(endpoint)
	try:
		with open(fp, "rb") as f:
			t = json.load(f)
			return ( t["token"], datetime.datetime.fromisoformat(t["expiry"]) )
	except (FileNotFoundError, json.JSONDecodeError):
		return

# initialise
prog = sys.argv[0]
try:
	rp, w = init_from_opts(sys.argv[1:])
except (UsageError, ValueError) as e:
	perr(str(e))
	perr("Run {prog} -h for help.".format(prog = prog))
	exit(OurMagic.EC.USAGE_ERR.value)

# install the token hook
w.on_new_token = on_new_token
w.on_load_token = on_load_token

# run
for c in rp.cmds:
	match c:
		case "help": print_help(sys.stdout, prog)
		case "version": print_version(sys.stdout)
		case "list": cmd_list(rp.directives.keys())
		case "exec": cmd_exec_dir(rp.directives.items())
		case "user-data": cmd_user_data()
