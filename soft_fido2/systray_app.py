import os, time, sys, subprocess, traceback

from PyQt6.QtGui import QIcon, QAction
from PyQt6.QtWidgets import QApplication, QSystemTrayIcon, QMenu
from PyQt6.QtCore import QObject, QThread, QRunnable, QThreadPool, pyqtSignal, pyqtSlot
try:
    from soft_fido2.uhid_device import QueueMessageType
except:
    from uhid_device import QueueMessageType


class Worker(QRunnable):
    def __init__(self, handle, *args, **kwargs):
        super().__init__()
        self.handle = handle
        self.args = args
        self.kwargs = kwargs
        self.error = pyqtSignal(tuple)

    @pyqtSlot()
    def run(self):
        try:
            self.handle(*self.args, **self.kwargs)
        except Exception:
            traceback.print_exc()
            exctype, value = sys.exc_info()[:2]
            self.error.emit((exctype, value, traceback.format_exc()))


class SysTrayIcon(QSystemTrayIcon):
    def __init__(self, uts_msg_queue, stu_msg_queue):
        self.uts_msg_queue = uts_msg_queue
        self.stu_msg_queue = stu_msg_queue
        self.main_icon = self._generate_icon()
        self.app = QApplication(sys.argv)
        super().__init__(self.main_icon, self.app)
        self.setToolTip('soft_fido2')
        self.menu = self._menu_setup()
        self.threadPool = self._threadpool_setup()
        self.worker = self._worker_setup()
        self.quit = False
        self._finalise()

    def _generate_icon(self):
        icon = None
        icon_path = os.path.join(os.environ.get("FIDO_HOME"), 'icon.png')
        if os.path.exists(icon_path):
            icon = QIcon(icon_path)
        else:
            icon = QIcon.fromTheme(QIcon.ThemeIcon.DialogPassword)
        return icon

    def _menu_setup(self):
        menu = QMenu()
        action_setup = [self.__generate_passkey_action_setup,
                        self.__manage_credentials_action_setup,
                        self.__exit_action_setup]
        for action in action_setup:
            menu.addAction(action())
        return menu

    def __generate_passkey_action_setup(self):
        action = QAction('Generate Passkey', self.app)
        action.triggered.connect(self.__generate_passkey)
        return action

    def __manage_credentials_action_setup(self):
        action = QAction('Manage Credentials', self.app)
        action.triggered.connect(self.__manage_credentials)
        return action

    def __exit_action_setup(self):
        action = QAction('Exit', self.app)
        action.triggered.connect(self._exit)
        return action

    def __generate_passkey(self):
        print('Generate Passkey')

    def __manage_credentials(self):
        print('Manage Credentials')

    def _threadpool_setup(self):
        threadpool = QThreadPool()
        threadpool.maxThreadCount()
        return threadpool

    def _worker_setup(self):
        return Worker(self._msg_queue_handler)

    def _msg_queue_handler(self):
        while not self.quit:
            time.sleep(0.001)
            if self.uts_msg_queue.qsize() > 0:
                msg = self.uts_msg_queue.get()
                if msg == QueueMessageType.USER_REQUEST:
                    self.setIcon(QIcon.fromTheme(QIcon.ThemeIcon.DialogWarning))
                    self.setToolTip('Requesting Authentication...')
                elif msg == QueueMessageType.AUTH_RESPONSE:
                    self.setIcon(self.main_icon)
                    self.setToolTip('soft_fido2')

    def _exit(self):
        self.stu_msg_queue.put(QueueMessageType.QUIT)
        self.quit = True
        self.app.quit()

    def _finalise(self):
        self.setContextMenu(self.menu)
        self.show()
        self.threadPool.start(self.worker)
        DesktopNotificationPrompt.open_notification()
        res = self.app.exec()
        self.hide()


class DesktopNotificationPrompt:
    ACCEPT = 0
    DECLINE = 1
    EXPIRE = 2

    @classmethod
    def prompt_notification(cls):
        timeout = 60000  # Expire notification in a minute
        cmd = ['notify-send',
            '--action=accept=Accept',
            '--action=decline=Decline',
            '--action=default=default',
            '--expire-time={}'.format(timeout),
            '--icon=info',
            '--app-name=soft_fido2',
            'soft_fido2 Authenticator',
            'An authentication attempt is being requested. Do you accept?']
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        outMsg, errMsg = proc.communicate()
        outMsg, errMsg = outMsg.decode('utf-8'), errMsg.decode('utf-8')

        if outMsg == 'accept\n' or outMsg == 'default\n':
            return cls.ACCEPT
        else:
            if errMsg == 'Wait timeout expired\n':
                return cls.EXPIRE
            else:
                return cls.DECLINE

    def open_notification():
        cmd = ['notify-send',
            '--app-name=soft_fido2',
            '--icon=info', 'soft_fido2 Authenticator',
            'Starting the EyeBeeKey Passkey UHID Service']
        subprocess.Popen(cmd).communicate()
