#!/usr/bin/env python3
"""Run socket regressions with a cellular host route and two selected networks.

Linux SO_MARK stands in for Android's network binding API. This verifies the
core's selection/binding behavior; it does not emulate netd or a cellular modem.
Only temporary network namespaces are changed. Run as root with a compiled
common/dialer test binary as the sole argument.
"""

import os
import select
import subprocess
import sys


def run(*args):
    subprocess.run(args, check=True)


client = f"box-network-client-{os.getpid()}"
server = f"box-network-server-{os.getpid()}"
created = []
echo = None
try:
    for ns in (client, server):
        run("ip", "netns", "add", ns)
        created.append(ns)
        run("ip", "-n", ns, "link", "set", "lo", "up")
    for name, subnet4, subnet6 in (
        ("wifi", "192.0.2", "2001:db8:1"),
        ("cell", "198.51.100", "2001:db8:2"),
    ):
        run("ip", "-n", client, "link", "add", name + "0", "type", "veth", "peer", "name", name + "1", "netns", server)
        for ns, suffix, host in ((client, "0", "2"), (server, "1", "1")):
            dev = name + suffix
            run("ip", "-n", ns, "addr", "add", f"{subnet4}.{host}/30", "dev", dev)
            run("ip", "-n", ns, "-6", "addr", "add", f"{subnet6}::{host}/64", "dev", dev, "nodad")
            run("ip", "-n", ns, "link", "set", dev, "up")
            run("ip", "netns", "exec", ns, "sysctl", "-q", "-w", f"net.ipv4.conf.{dev}.rp_filter=0")
    for ns in (client, server):
        run("ip", "netns", "exec", ns, "sysctl", "-q", "-w", "net.ipv4.conf.all.rp_filter=0")
    run("ip", "-n", server, "addr", "add", "203.0.113.1/32", "dev", "lo")
    run("ip", "-n", server, "-6", "addr", "add", "2001:db8:ffff::1/128", "dev", "lo", "nodad")
    for family, destination, wifi_gateway, cell_gateway in (
        ("-4", "203.0.113.1/32", "192.0.2.1", "198.51.100.1"),
        ("-6", "2001:db8:ffff::1/128", "2001:db8:1::1", "2001:db8:2::1"),
    ):
        run("ip", "-n", client, family, "route", "add", "default", "via", wifi_gateway, "dev", "wifi0")
        run("ip", "-n", client, family, "route", "add", "table", "99", destination, "via", cell_gateway, "dev", "cell0", "onlink")
        run("ip", "-n", client, family, "rule", "add", "priority", "10000", "lookup", "99")
        for handle, gateway, dev in (("101", wifi_gateway, "wifi0"), ("102", cell_gateway, "cell0")):
            run("ip", "-n", client, family, "route", "add", "table", handle, "default", "via", gateway, "dev", dev, "onlink")
            run("ip", "-n", client, family, "rule", "add", "priority", "9000", "fwmark", handle, "lookup", handle)
    echo = subprocess.Popen(
        ["ip", "netns", "exec", server, "python3", "-u", "-c", """
import asyncio
async def echo(reader, writer):
    try:
        data = await reader.readexactly(4)
        writer.write(data)
        await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionError):
        pass
    finally:
        writer.close()
async def main():
    servers = [await asyncio.start_server(echo, '203.0.113.1', 18080),
               await asyncio.start_server(echo, '2001:db8:ffff::1', 18080)]
    print('READY', flush=True)
    await asyncio.Future()
asyncio.run(main())
"""], stdout=subprocess.PIPE, text=True,
    )
    ready, _, _ = select.select([echo.stdout], [], [], 10)
    if not ready or echo.stdout.readline().strip() != "READY":
        raise RuntimeError("policy-route echo fixture failed to start")
    run("ip", "netns", "exec", client, "env", "SING_BOX_TEST_ANDROID_POLICY_ROUTES=1", os.path.abspath(sys.argv[1]), "-test.run=^TestPlatformNetworkDestinationRoute$", "-test.v", "-test.timeout=30s")
finally:
    if echo is not None:
        echo.terminate()
        try:
            echo.wait(timeout=5)
        except subprocess.TimeoutExpired:
            echo.kill()
            echo.wait()
    for ns in reversed(created):
        subprocess.run(["ip", "netns", "del", ns], check=False)
