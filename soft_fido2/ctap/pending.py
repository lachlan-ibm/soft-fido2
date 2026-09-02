# Copyright IBM Corp. 2022, 2025
# IBM Confidential

"""Background keepalive thread for CTAPHID connections."""

import threading, time

from .packet import CTAPHIDInitPkt, bcolors, colour_print


class KeepAliveWorker(threading.Thread):
    """
    Background thread that sends CTAPHID keepalive messages.
    
    CTAP2 Status Codes (per CTAP2 spec Section 11.2.9.1.7):
    - 0x01: STATUS_PROCESSING - The authenticator is still processing the current request
    - 0x02: STATUS_UPNEEDED - The authenticator is waiting for user presence
    
    Note: CTAPHID_KEEPALIVE command code is 0x3B per CTAP2 specification.
    """

    cid = b'0xFFFFFFFF'
    not_alive = False
    uhid = None

    def __init__(self, pending, cid, status_code=0x02, interval_ms=100):
        """
        Initialize KeepAliveWorker.
        
        Args:
            pending: Queue to send keepalive packets to
            cid: Channel ID for the CTAPHID connection
            status_code: CTAP2 status code (0x01=processing, 0x02=waiting for UP)
            interval_ms: Interval in milliseconds between keepalive messages (default: 100ms)
        """
        super().__init__()
        self.pending = pending
        self.cid = cid
        self.status_code = status_code
        self.interval_ms = interval_ms

    def run(self):
        interval_sec = self.interval_ms / 1000.0
        while self.not_alive == False:
            time.sleep(interval_sec)
            
            # Log keepalive with status code description
            status_desc = {
                0x01: 'STATUS_PROCESSING',
                0x02: 'STATUS_UPNEEDED'
            }.get(self.status_code, f'UNKNOWN(0x{self.status_code:02x})')
            
            colour_print(colour=bcolors.FAIL, component='KeepAliveWorker.run',
                        msg=f'Sending keepalive with status {status_desc} (0x{self.status_code:02x})')
            
            # Send keepalive packet with correct CTAPHID_KEEPALIVE command (0x3B per spec)
            rsp = CTAPHIDInitPkt(cid=int.from_bytes(self.cid, 'big'),
                                  cmd=0x3B,  # CTAPHID_KEEPALIVE per CTAP2 spec
                                  bcnt=0x01,
                                  data=bytes([self.status_code])).pack()
            self.pending.put(rsp)

    def interrupt(self):
        """Stop the keepalive worker thread."""
        self.not_alive = True
