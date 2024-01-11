# EC2IMDS
The ec2imds python package is a module and a cli tool for retrieving AWS EC2
instance meta data and user data from the Instance Meta Data Service endpoint.
It is an improved version of [ec2metadata](https://github.com/canonical/cloud-utils/blob/main/bin/ec2metadata).

The cli tool prints data in JSON formate to stdout. The module consists of
"low-level" utils for traversing the IMDS directory.

## Install
```sh
pip install ec2imds
```

## CLI Usage
On an EC2 instance, run the module.

```sh
# Get everything
python -m ec2imds

# Download user data(treated as binary)
python -m ec2imds -U > userdata

# Get specific categories
python -m ec2imds meta-data/instance-id meta-data/public-ipv4

# Get categories matching the regex
python -m ec2imds -E 'meta-data/placement/.*'

# List all implemented categories
python -m ec2imds -L
```

For more info on usage, run `python -m ec2imds -h`.

The cli tool can be used from a shell script in conjunction with `jq`.

## Module Usage
ec2imds uses IMDS v2 only. The IMDS v2 mandates the use of token. `IMDSWrapper`
provides callbacks for saving and loading tokens when sending requests to the
IMDS endpoint. Incorporate the callbacks to suit your use case. You can use
`IMDSWrapper` without the callbacks, but you may face issues from token
exhaustion in the long run. Following is a simple example from the cli tool.

```py
import datetime
import json
import os

from ec2imds import *

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
```

Where

- `rp.t` is the path to the token directory.

In the token directory, a file will be created to save the taken value and its
expiry for each IMDS endpoints, `169.254.169.254:80` and `[fd00:ec2::254]:80`.

Now, functions for fetching categories are defined in `IMDSWrapper.dir_dict`.

```py
# Instantiate and set up
w = IMDSWrapper()
w.on_new_token = on_new_token
w.on_load_token = on_load_token

# Get all meta data
all_meta = w.all()

# Get user data
try:
	with (w.open_userdata() as u, open("file", "wb") as f):
		while f.write(w.read(4096)): pass
except:
	...

# Get specific meta data
instance_id = w.dir_dict["meta-data/instance-id"].func()

# Cycle through
for k, v in w.dir_dict.items():
	if k.startswith("meta-data/placement/"):
		print(v.func())
```

Note that for requests ended in 404, the functions return `None`.

The module does not define any classes for returned meta data. The functions
always return `dict` for directory data and `str`, `int`, `bool` ... for scalar
values. The module is, per se, a low-level util for fetching data from the IMDS.

## IPv6 Considerations
See [doc/ipv6only.md](doc/ipv6only.md).
