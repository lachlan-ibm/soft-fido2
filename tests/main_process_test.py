#!/usr/bin/env python3
# Copyright IBM Corp. 2025
# IBM Confidential
#
# OS-persona integration tests for soft_fido2/__main__.py
#
# Emulates the role of the Linux kernel HID driver using a socat PTY bridge.
# socat creates two raw PTY endpoints (rawer mode — no line discipline, no
# 4096-byte limit):
#
#   kern_fd  <──────── socat PTY bridge ────────>  dev_path
#   (test)                                          (CTAPHIDevice thread)
#
# The test writes UHIDOutputEvent frames to kern_fd and reads UHIDInput2Event
# frames back — exactly as the Linux kernel does on /dev/uhid.
# No mocking. No production code changes.
#
# Scope: HID report descriptor, CTAPHID channel negotiation, getInfo response.
# Out of scope: GUI, USB/IP, makeCredential, getAssertion, PIN/TPM.

import os
import sys
import time
import fcntl
import socket
import struct
from typing import Any
import cbor2 as cbor
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from soft_fido2.__main__ import DeviceManager
from soft_fido2.platform.uhid_device import (
    REPORT_DESCRIPTOR,
    UHIDCreate2Event,
    UHIDOutputEvent,
    UHIDEventType,
    EV_MAX_SIZE,
)
from soft_fido2.ctap.constants import CBORStatusCode


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BROADCAST_CID     = bytes([0xFF, 0xFF, 0xFF, 0xFF])
CTAPHID_INIT_CMD  = 0x86   # 0x06 | 0x80
CTAPHID_CBOR_CMD  = 0x90   # 0x10 | 0x80
GET_INFO_CMD_BYTE = 0x04
MAX_FRAME         = 64

# Fixed wire sizes for each event type the device can write to kern_fd.
# UHIDCreate2Event : type(4)+name(128)+phys(64)+uniq(64)+rd_size(2)+bus(2)
#                   +vendor(4)+product(4)+version(4)+country(4)+rd_data(4096) = 4376
# UHIDInput2Event  : type(4)+ev_len(2)+data(4096) = 4102
# UHIDDestroyEvent : type(4) only = 4  (written by destroy_ev)
_EV_WIRE_SIZE = {
    UHIDEventType.CREATE2.value : 4 + 128 + 64 + 64 + 2 + 2 + 4 + 4 + 4 + 4 + 4096,  # 4376
    UHIDEventType.INPUT2.value  : 4 + 2 + 4096,                                         # 4102
    UHIDEventType.DESTROY.value : 4,
}


# ---------------------------------------------------------------------------
# Frame helpers
# ---------------------------------------------------------------------------

def _build_ctaphid_init_frame(nonce: bytes) -> bytes:
    """64-byte CTAPHID INIT frame on the broadcast CID."""
    assert len(nonce) == 8
    frame = (
        bytes([0x00])             +   # endpoint byte
        BROADCAST_CID             +   # CID: 0xFFFFFFFF
        bytes([CTAPHID_INIT_CMD]) +   # CMD: 0x86
        len(nonce).to_bytes(2, 'big') +
        nonce
    )
    return frame.ljust(MAX_FRAME, b'\x00')


def _build_ctaphid_get_info_frame(cid: bytes) -> bytes:
    """64-byte CTAPHID CBOR GET_INFO frame on the given CID."""
    assert len(cid) == 4
    cbor_payload = bytes([GET_INFO_CMD_BYTE])
    frame = (
        bytes([0x00])             +   # endpoint byte
        cid                       +   # negotiated CID
        bytes([CTAPHID_CBOR_CMD]) +   # CMD: 0x90
        len(cbor_payload).to_bytes(2, 'big') +
        cbor_payload
    )
    return frame.ljust(MAX_FRAME, b'\x00')


def _wrap_as_uhid_output_event(hid_frame: bytes) -> bytes:
    """Wrap a 64-byte HID frame in a UHIDOutputEvent structure.

    This is what the kernel writes to /dev/uhid when the host sends an
    HID output report to the device.
    """
    ev = UHIDOutputEvent(
        event=UHIDEventType.OUTPUT.value,
        ev_len=MAX_FRAME,
        data=hid_frame.ljust(4096, b'\x00'),
    )
    return ev.pack()


def _read_response_frames(kern_fd: int, count: int, timeout: float = 3.0) -> list[bytes]:
    """Read UHIDInput2Event frames the device thread writes back.

    Returns list of raw HID payloads (up to 64 bytes each), stopping when
    `count` frames have been collected or `timeout` seconds have elapsed.

    Uses a type-aware parser: peek at the 4-byte event type, look up the
    exact wire size for that event, consume precisely that many bytes, then
    skip anything that isn't INPUT2.  This correctly steps over the
    UHIDCreate2Event (4376 bytes) that the device writes at startup without
    misaligning the stream.
    """
    frames = []
    deadline = time.monotonic() + timeout
    buf = b''
    _MIN_HEADER = 4  # enough to read the event type

    while len(frames) < count and time.monotonic() < deadline:
        try:
            chunk = os.read(kern_fd, EV_MAX_SIZE * 4)
            buf += chunk
        except BlockingIOError:
            time.sleep(0.005)
            continue

        while len(buf) >= _MIN_HEADER:
            ev_type = struct.unpack_from('<I', buf, 0)[0]
            ev_sz   = _EV_WIRE_SIZE.get(ev_type)
            if ev_sz is None:
                # Unknown event type — discard one byte and resync.
                buf = buf[1:]
                continue
            if len(buf) < ev_sz:
                break  # wait for more data
            raw = buf[:ev_sz]
            buf = buf[ev_sz:]
            if ev_type == UHIDEventType.INPUT2.value:
                ev_len = struct.unpack_from('<H', raw, 4)[0]
                frames.append(raw[6 : 6 + ev_len])

    return frames


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture()
def uhid_env(tmp_path, monkeypatch):
    """Start a CTAPHIDevice thread with only os.open mocked.

    A Unix socket pair replaces /dev/uhid:
      kern_sock  <──── SOCK_STREAM ────>  dev_sock
      (test)                              (UserDevice.run fd)

    Only os.open inside soft_fido2.platform.uhid_device is patched — it returns
    dev_sock.fileno() instead of opening a real path.  All os.read /
    os.write calls in production code are untouched and operate on the
    real socket fd.  No PTY, no socat, no 4096-byte kernel buffer limit.
    """
    monkeypatch.setenv("FIDO_HOME", str(tmp_path))
    monkeypatch.setenv("SOFT_FIDO2_SKIP_UP", "true")
    monkeypatch.setenv("SOFT_FIDO2_DEBUG_LEVEL", "ERROR")

    kern_sock, dev_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    # kern side: non-blocking so the test can poll
    fcntl.fcntl(kern_sock.fileno(), fcntl.F_SETFL, os.O_NONBLOCK)
    # dev side: non-blocking to match O_NONBLOCK set by UserDevice.run
    fcntl.fcntl(dev_sock.fileno(), fcntl.F_SETFL, os.O_NONBLOCK)

    dev_fd = dev_sock.fileno()

    import soft_fido2.platform.uhid_device as _uhid_mod
    real_os_open = os.open

    def _mock_open(path, flags, *args, **kwargs):
        # Only intercept the uhid device path; pass everything else through.
        if path == "/dev/uhid_test_mock":
            return dev_fd
        return real_os_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(_uhid_mod.os, "open", _mock_open)

    kern_fd = kern_sock.fileno()

    manager = DeviceManager(device_path="/dev/uhid_test_mock")
    manager.start_device()

    # Drain the UHIDCreate2Event the device thread writes at startup
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        try:
            data = os.read(kern_fd, EV_MAX_SIZE * 2)
            if data:
                break
        except BlockingIOError:
            time.sleep(0.01)

    yield kern_fd, manager

    manager.stop_device(timeout=3)
    # dev_sock fd is closed by UserDevice.run's finally block — don't double-close.
    kern_sock.close()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestHIDReportDescriptor:
    """Static checks on the FIDO HID report descriptor — no device needed."""

    def test_usage_page_is_fido_alliance(self):
        """First three bytes declare the FIDO Alliance usage page (0xF1D0)."""
        assert REPORT_DESCRIPTOR[0:3] == bytes([0x06, 0xD0, 0xF1])

    def test_usage_is_u2f_authenticator(self):
        assert REPORT_DESCRIPTOR[3:5] == bytes([0x09, 0x01])

    def test_input_and_output_report_count_is_64_bytes(self):
        # REPORT_COUNT (0x95) 0x40 must appear for both input and output reports
        positions = [
            i for i in range(len(REPORT_DESCRIPTOR) - 1)
            if REPORT_DESCRIPTOR[i] == 0x95 and REPORT_DESCRIPTOR[i + 1] == 0x40
        ]
        assert len(positions) == 2, \
            "Expected REPORT_COUNT(64) for both input and output reports"

    def test_create2_event_embeds_descriptor(self):
        packed = UHIDCreate2Event().pack()
        assert REPORT_DESCRIPTOR in packed

    def test_create2_event_rd_size_matches_descriptor_length(self):
        ev = UHIDCreate2Event()
        assert getattr(ev, "rd_size") == len(REPORT_DESCRIPTOR)


class TestCIDNegotiationAndGetInfo:
    """End-to-end OS persona: negotiate a CID then issue GET_INFO on it."""

    def _do_ctaphid_init(self, kern_fd: int, nonce: bytes) -> bytes:
        """Send CTAPHID_INIT on broadcast CID, return the 4-byte assigned CID."""
        os.write(kern_fd, _wrap_as_uhid_output_event(_build_ctaphid_init_frame(nonce)))

        responses = _read_response_frames(kern_fd, count=1, timeout=3.0)
        assert len(responses) >= 1, "No CTAPHID_INIT response received"

        resp = responses[0]
        # Response layout (ctaphid_init):
        #   CID(4) + CMD(1) + BCNT(2) + NONCE(8) + ASSIGNED_CID(4) + proto(1) + ver(3) + caps(1)
        assert resp[0:4] == BROADCAST_CID,    "Response CID must echo broadcast CID"
        assert resp[4]   == CTAPHID_INIT_CMD, "Response CMD must be CTAPHID_INIT"
        assert resp[7:15] == nonce,           "Nonce must be echoed verbatim"

        assigned_cid = resp[15:19]
        assert assigned_cid != BROADCAST_CID, "Assigned CID must not be broadcast"

        # INIT response payload: nonce(8)+cid(4)+proto(1)+major(1)+minor(1)+build(1)+caps(1)
        # Frame layout: CID(4)+CMD(1)+BCNT(2)+payload → payload starts at byte 7
        # capabilities byte is at offset 7+8+4+4 = 23
        capabilities = resp[23]
        assert capabilities & 0x04, "CAPABILITY_CBOR (0x04) must be set"
        assert capabilities & 0x01, "CAPABILITY_WINK (0x01) must be set"

        return assigned_cid

    def _do_get_info(self, kern_fd: int, cid: bytes) -> dict[int, Any]:
        """Send GET_INFO on `cid`, reassemble response frames, return decoded CBOR."""
        os.write(kern_fd, _wrap_as_uhid_output_event(_build_ctaphid_get_info_frame(cid)))

        frames = _read_response_frames(kern_fd, count=8, timeout=3.0)
        assert len(frames) >= 1, "No GET_INFO response received"

        # First frame: CID(4) + CMD(1) + BCNT(2) + payload
        # Continuation frames: CID(4) + SEQ(1) + payload
        first   = frames[0]
        bcnt    = int.from_bytes(first[5:7], 'big')
        payload = bytearray(first[7:])
        for cont in frames[1:]:
            payload += bytearray(cont[5:])
        payload = bytes(payload[:bcnt])

        assert payload[0] == CBORStatusCode.CTAP2_OK, \
            f"Expected CTAP2_OK (0x00), got 0x{payload[0]:02x}"

        return cbor.loads(payload[1:])

    def test_negotiate_cid_then_get_info_ctap2(self, uhid_env):
        """CTAPHID_INIT → GET_INFO: verify FIDO2 versions and capabilities."""
        kern_fd, _ = uhid_env

        nonce        = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        assigned_cid = self._do_ctaphid_init(kern_fd, nonce)
        info         = self._do_get_info(kern_fd, assigned_cid)

        # versions (key 0x01)
        assert "FIDO_2_1" in info[0x01],       "FIDO_2_1 must be advertised"
        assert "FIDO_2_0" in info[0x01],       "FIDO_2_0 must be advertised"
        assert "U2F_V2" not in info[0x01],     "U2F_V2 must not appear in CTAP2 mode"

        # extensions (key 0x02)
        assert "hmac-secret" in info[0x02],    "hmac-secret extension must be present"

        # options (key 0x04)
        opts = info[0x04]
        assert opts.get("rk")        is True,  "rk must be True"
        assert opts.get("up")        is True,  "up must be True"
        assert opts.get("clientPin") is True,  "clientPin must be True"

        # pinUvAuthProtocols (key 0x06)
        assert 1 in info[0x06],                "PIN protocol 1 must be listed"

    def test_negotiate_cid_then_get_info_ctap1_mode(self, uhid_env, tmp_path):
        """Same session flow with platform.cfg forcing ctap1 mode."""
        import json
        (tmp_path / "platform.cfg").write_text(json.dumps({"ctap_version": "ctap1"}))

        kern_fd, _ = uhid_env

        nonce        = bytes([0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x08])
        assigned_cid = self._do_ctaphid_init(kern_fd, nonce)
        info         = self._do_get_info(kern_fd, assigned_cid)

        assert "U2F_V2"   in info[0x01],     "U2F_V2 must be advertised in CTAP1 mode"
        assert "FIDO_2_0" in info[0x01],     "FIDO_2_0 must be advertised in CTAP1 mode"
        assert "FIDO_2_1" not in info[0x01], "FIDO_2_1 must not appear in CTAP1 mode"
        assert 0x06 not in info,             "pinUvAuthProtocols must be absent in CTAP1 mode"
