# Using it in IPv6 only environment
The module works in both dual-stack and IPv6 only environment. Recenly, running
EC2 instances in IPv6 only subnets has become an option to consider[^1] [^2].

The module implements rfc8305.

There are quite a few set ups you need to do.

## Instance Metadata Options[^3]
The IPv6 IMDS endpoint is not enabled by default even if the instance is
launched in an IPv6 subnet.

For instances already launched, refer following[^4].

```bash
aws ec2 modify-instance-metadata-options \
	--instance-id <your-instance-id> \
	--http-protocol-ipv6 enabled
```

When launching instances or making launch templates using AWS Management
Console, enable "**Metadata transport**" in the "**Advanced details**".[^5]

## More
For more info, visit
https://github.com/dxdxdt/gists/tree/master/writeups/ec2-ipv6-only/ec2-ipv6-only.md
