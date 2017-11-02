# Early Hints Plugin

This plugin enables TS to trigger HTTP/2 Server Push,
when TS receive 103 Early Hints Status Code

Details about 103 Early Hints is described in draft-kazuho-early-hints-status-code-00
- https://tools.ietf.org/html/draft-kazuho-early-hints-status-code-00

# Quick install:

Make sure devel packages for traffic-server are installed.
Make sure that 'tsxs' is in your path.

	make -f Makefile.tsxs
	make -f Makefile.tsxs install

Add 'early-hints.so' to plugin.config.

Restart traffic-server.

# Example

When origin server response below

```
GET / HTTP/1.1
Host: example.com

```
