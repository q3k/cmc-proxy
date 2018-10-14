Dell M1000e gRPC Proxy
======================

Cursedness level: 6.5/10.

This is a small gRPC proxy to allow programmatic access to a Dell M1000e Chassis Management Controller. It's based on scraping the web interface, as the alternative (WSMAN) is even more ridiculous.

Functionality
-------------

The only feature supported so far is getting information for an iDRAC KVM console. This can be used to run a iDRAC KVM proxy (to be implemented), or the original client.

Usage
-----

    ./cmc-proxy -h

Flags are self-explanatory. This is based on [hspki](https://code.hackerspace.pl/q3k/hspki), so you'll need to have compatible (dev) certs to run this. The proxy listens on gRPC and a status HTTP debug server.
