"""Exercise the packaged offline Web entry point using a synthetic capture."""

import http.client
import json
import pathlib
import select
import signal
import struct
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit


def capture_file(path):
    frame = bytes.fromhex(
        "0200000000020200000000010800"
        "450000200000000040110000c0000201c6336402"
        "c0010035000c0000"
    ) + b"test"
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    packet = struct.pack("<IIII", 1700000000, 123456, len(frame), len(frame))
    path.write_bytes(header + packet + frame)


def check(binary, file):
    child = subprocess.Popen(
        [binary, "serve", "--port", "0", "--input", str(file)],
        stdout=subprocess.PIPE,
        text=True,
    )
    events = None
    try:
        assert select.select([child.stdout], [], [], 10)[0], "server did not start"
        origin = child.stdout.readline().strip().split()[-1]
        port = urlsplit(origin).port

        def request(path, *, method="GET", headers=None, expected=200):
            with_client = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            try:
                with_client.request(method, path, headers=headers or {})
                response = with_client.getresponse()
                body = response.read()
                assert response.status == expected, (path, response.status, body)
                assert response.getheader("Cache-Control") == "no-store" or expected == 403
                if response.getheader("Content-Type", "").startswith("application/json"):
                    return json.loads(body)
                return body
            finally:
                with_client.close()

        assert b"Wiretuna" in request("/")
        assert b"PacketList" in request("/assets/packets.js")
        for invalid_host in ("wrong.example", "localhost.wrong.example", "localhost:99999"):
            request("/api/v1/sessions", headers={"Host": invalid_host}, expected=403)
        forwarded_host = "localhost:62634" if port != 62634 else "localhost:62635"
        forwarded_origin = "http://" + forwarded_host
        assert b"Wiretuna" in request("/", headers={"Host": forwarded_host})
        for _ in range(100):
            capture = request("/api/v1/sessions")["sessions"][0]
            if capture["phase"] == "finished":
                break
            time.sleep(0.025)
        assert capture["phase"] == "finished", capture
        base = "/api/v1/sessions/" + capture["id"]
        listing = request(base + "/packets?filter=udp.dstport%20%3D%3D%2053")
        assert listing["cursor"] == "1" and len(listing["packets"]) == 1, listing
        packet = request(base + "/packets/1")
        assert packet["layers"][-1]["name"] == "UDP", packet
        assert request(base + "/packets/1/bytes?offset=42&limit=4") == b"test"
        request(base + "/packets?filter=unknown", expected=400)
        request(base, method="DELETE", expected=403)

        events = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        events.request("GET", base + "/events")
        response = events.getresponse()
        assert response.readline() == b"event: status\n"
        request(
            base, method="DELETE",
            headers={"Host": forwarded_host, "Origin": origin}, expected=403,
        )
        request(
            base, method="DELETE",
            headers={"Host": forwarded_host, "Origin": forwarded_origin}, expected=204,
        )
        assert request("/api/v1/sessions") == {"sessions": []}
        child.send_signal(signal.SIGTERM)
        assert child.wait(timeout=5) == 0
    finally:
        if events:
            events.close()
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as directory:
        fixture = pathlib.Path(directory) / "sample.pcap"
        capture_file(fixture)
        check(str(pathlib.Path(sys.argv[1]).resolve()), fixture)
    print("Embedded assets, pcap playback, filtering, packet bytes, SSE and shutdown passed.")
