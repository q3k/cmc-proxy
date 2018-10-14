Dell M1000e gRPC Proxy
======================

Cursedness level: 6.5/10 (regexp XML parsing, JSONP scraping, limited sessions).

This is a small gRPC proxy to allow programmatic access to a Dell M1000e Chassis Management Controller. It's based on scraping the web interface, as the alternative (WSMAN) is even more ridiculous.

Functionality
-------------

The only feature supported so far is getting information for an iDRAC KVM console. This can be used to run a iDRAC KVM proxy (to be implemented), or the original client.

Usage
-----

    ./cmc-proxy -h

Flags are self-explanatory. This is based on [hspki](https://code.hackerspace.pl/q3k/hspki), so you'll need to have compatible (dev) certs to run this. The proxy listens on gRPC and a status HTTP debug server.

Example
-------

    $ grpc-dev -d '{"blade_num": 6}' cmc.q3k.svc.cluster.local:4200 proto.CMCProxy.GetKVMData
    {
      "arguments": [
        "10.10.10.16:443",
        "5901",
        "oojo2obohhaWiu3A",
        "1",
        "0",
        "3668",
        "3669",
        "511",
        "5900",
        "1",
        "EN"
      ]
    }

