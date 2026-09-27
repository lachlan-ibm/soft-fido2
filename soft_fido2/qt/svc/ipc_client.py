# Copyright IBM 2022, 2025
# IBM Confidential

"""IPC client for communicating with a running soft_fido2 instance.

Sends a command string over a QLocalSocket to the well-known socket path
that the running instance's QLocalServer is listening on.

Example:
    client = IpcClient()
    delivered = client.send("open_settings")
"""

import logging
import sys

from PyQt6.QtNetwork import QLocalSocket
from PyQt6.QtCore import QCoreApplication, QStandardPaths


def ipc_socket_path() -> str:
    """Return the absolute socket path used by both server and client.
    """
    runtime = QStandardPaths.writableLocation(
        QStandardPaths.StandardLocation.RuntimeLocation
    )
    return runtime + "/soft_fido2_ipc.sock"


class IpcClient:
    """Sends a single IPC command to the running soft_fido2 instance."""

    def __init__(self, connect_timeout_ms: int = 500):
        self._timeout = connect_timeout_ms
        # QCoreApplication is sufficient for QLocalSocket and avoids
        # triggering the desktop portal registration that QApplication does,
        # which would conflict with the already-running service instance.
        self._app = QCoreApplication.instance() or QCoreApplication(sys.argv)

    def send(self, cmd: str) -> bool:
        """Send *cmd* to the running instance.

        Returns:
            True  — command delivered successfully.
            False — no running instance found (connect timed out).
        """
        path = ipc_socket_path()
        socket = QLocalSocket()
        socket.connectToServer(path)
        if not socket.waitForConnected(self._timeout):
            logging.warning("No running soft_fido2 instance found.")
            return False
        socket.write(cmd.encode("utf-8"))
        socket.flush()
        socket.disconnectFromServer()
        return True
