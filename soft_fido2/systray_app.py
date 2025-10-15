# Copyrite IBM 2022, 2025
# IBM Confidential

import os, time, sys, subprocess, traceback, shutil, threading

from PyQt6.QtGui import QIcon, QAction
from PyQt6.QtWidgets import QApplication, QSystemTrayIcon, QMenu
from PyQt6.QtCore import QObject, QRunnable, QThreadPool, pyqtSignal, pyqtSlot
try:
    from soft_fido2.message_queues import QueueMessageType, MessageQueue
except:
    from message_queues import QueueMessageType, MessageQueue

class WorkerSignals(QObject):
    # Define signals as class attributes here
    error = pyqtSignal(tuple)

class Worker(QRunnable):
    def __init__(self, handle, *args, **kwargs):
        super().__init__()
        self.handle = handle
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()

    @pyqtSlot()
    def run(self):
        try:
            self.handle(*self.args, **self.kwargs)
        except Exception:
            traceback.print_exc()
            exctype, value = sys.exc_info()[:2]
            self.signals.error.emit((exctype, value, traceback.format_exc()))


class SysTrayIcon(QSystemTrayIcon):
    class NotificationFramework:
        NOTIFY_SEND = 0
        QT = 1

    def __init__(self):
        self.app = QApplication(sys.argv)
        self.main_icon = self._generate_icon('../icons/main_icon.png', QIcon.ThemeIcon.DialogPassword)
        self.auth_icon = self._generate_icon('../icons/auth_request.png', QIcon.ThemeIcon.DialogWarning)
        super().__init__(self.main_icon, self.app)
        self.setToolTip('soft_fido2')
        self.menu = self._menu_setup()
        self.notification_fw = self._setup_notifications()
        self.threadPool = self._threadpool_setup()
        self.worker = self._worker_setup()
        self.quit = False
        self._finalise()

    def _setup_notifications(self):
        if shutil.which('notify-send'):
            return self.NotificationFramework.NOTIFY_SEND
        else:
            self.messageClicked.connect(self.on_message_clicked)
            return self.NotificationFramework.QT

    def launch_notification(self):
        return {
            self.NotificationFramework.NOTIFY_SEND: NotifySend.launch_notification,
            self.NotificationFramework.QT: self._launch_notification_fallback
            }.get(self.notification_fw, self._launch_notification_fallback)()

    def prompt_notification(self):
        return {
            self.NotificationFramework.NOTIFY_SEND: NotifySend.prompt_notification,
            self.NotificationFramework.QT: self._prompt_notification_fallback
            }.get(self.notification_fw, self._prompt_notification_fallback)()

    def cancel_notification(self):
        NotifySend.cancel_notification()

    def _launch_notification_fallback(self):
        self.showMessage("soft_fido2 Authenticator", "Starting the EyeBeeKey Passkey UHID Service", QSystemTrayIcon.MessageIcon.Information, 5000)

    def _prompt_notification_fallback(self):
        self.showMessage("soft_fido2 Authenticator", "Authenticator is making a request. Do you accept?", QSystemTrayIcon.MessageIcon.Critical, 60000)

    def on_message_clicked(self):
        MessageQueue.udev_get.put(QueueMessageType.USER_RESPONSE_ACCEPT)

    def _menu_setup(self):
        menu = QMenu()
        action_setup = [self.__generate_passkey_action_setup,
                        self.__manage_credentials_action_setup,
                        self.__exit_action_setup]
        for action in action_setup:
            menu.addAction(action())
        return menu

    def _generate_icon(self, path, fallback):
        icon = None
        icon_path = os.path.join(os.getcwd(), path)
        if os.path.exists(icon_path):
            icon = QIcon(icon_path)
        else:
            icon = QIcon.fromTheme(fallback)
        return icon

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
        notif_threads = []
        while not self.quit:
            time.sleep(0.001)
            if MessageQueue.notify_sysapp.qsize() > 0:
                msg = MessageQueue.notify_sysapp.get()
                if msg == QueueMessageType.USER_REQUEST:
                    t = threading.Thread(target=self.prompt_notification)
                    t.start()
                    notif_threads.append(t)
                    self.setIcon(self.auth_icon)
                    self.setToolTip('Requesting Authentication...')
                elif msg == QueueMessageType.AUTH_RESPONSE:
                    self.cancel_notification()
                    self.setIcon(self.main_icon)
                    self.setToolTip('soft_fido2')
            tempThreadList = []
            for t in notif_threads:
                if not t.is_alive():
                    t.join()
                    tempThreadList.append(t)
            for t in tempThreadList:
                notif_threads.remove(t)

    def _exit(self):
        MessageQueue.notify_udev.put(QueueMessageType.QUIT)
        if self.notification_fw == self.NotificationFramework.NOTIFY_SEND:
            NotifySend.cancel_notification()
        self.quit = True
        self.app.quit()

    def _finalise(self):
        self.setContextMenu(self.menu)
        self.show()
        self.threadPool.start(self.worker)
        self.launch_notification()
        res = self.app.exec()
        self.hide()


class NotifySend:
    ACCEPT = 0
    DECLINE = 1
    EXPIRE = 2

    proc = None

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
            'Authenticator is making a request. Do you accept?']
        cls.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        while cls.proc.poll() is None:
            time.sleep(0.002)
        outMsg, errMsg = cls.proc.communicate()
        outMsg, errMsg = outMsg.decode('utf-8'), errMsg.decode('utf-8')

        if outMsg == 'accept\n' or outMsg == 'default\n':
            MessageQueue.udev_get.put(QueueMessageType.USER_RESPONSE_ACCEPT)
        else:
            MessageQueue.udev_get.put(QueueMessageType.USER_RESPONSE_REJECT)

    @classmethod
    def cancel_notification(cls):
        if cls.proc:
            cls.proc.terminate()

    @classmethod
    def launch_notification(cls):
        cmd = ['notify-send',
            '--app-name=soft_fido2',
            '--icon=info', 'soft_fido2 Authenticator',
            'Starting the EyeBeeKey Passkey UHID Service']
        subprocess.Popen(cmd).communicate()
