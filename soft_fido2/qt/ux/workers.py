"""Worker utilities for Qt threading.

This module provides utilities for executing background tasks in Qt applications
using QThreadPool. It implements a signal-based communication pattern between
worker threads and the main Qt event loop.

Threading Model:
    - Worker tasks run in QThreadPool threads (not the main Qt thread)
    - Communication back to main thread happens via Qt signals
    - Signals are thread-safe and automatically marshalled to main thread
    - Use WorkerSignals to emit results, errors, and completion notifications

Example:
    def long_running_task(param1, param2):
        # Do work here
        return result
    
    worker = Worker(long_running_task, param1, param2)
    worker.signals.result.connect(handle_result)
    worker.signals.error.connect(handle_error)
    worker.signals.finished.connect(handle_finished)
    QThreadPool.globalInstance().start(worker)
"""

import sys
import traceback
from PyQt6.QtCore import QObject, QRunnable, pyqtSignal, pyqtSlot


class WorkerSignals(QObject):
    """Signals for communicating from worker threads to main thread.
    
    Attributes:
        error: Signal emitted when worker encounters an exception.
               Emits tuple of (exception_type, exception_value, traceback_string)
        result: Signal emitted when worker completes successfully.
                Emits the return value from the worker function
        finished: Signal emitted when worker completes (success or failure)
    """
    # Define signals as class attributes here
    error = pyqtSignal(tuple)
    result = pyqtSignal(object)  # Signal for returning results
    finished = pyqtSignal()      # Signal when work is complete


class Worker(QRunnable):
    """Runnable worker for executing tasks in QThreadPool.
    
    This class wraps a callable and its arguments, executing them in a
    background thread and communicating results back via signals.
    
    Args:
        handle: Callable to execute in background thread
        *args: Positional arguments to pass to handle
        **kwargs: Keyword arguments to pass to handle
    
    Attributes:
        signals: WorkerSignals instance for communication with main thread
    
    Example:
        def my_task(x, y):
            return x + y
        
        worker = Worker(my_task, 5, 10)
        worker.signals.result.connect(lambda result: print(f"Result: {result}"))
        QThreadPool.globalInstance().start(worker)
    """
    
    def __init__(self, handle, *args, **kwargs):
        super().__init__()
        self.handle = handle
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()

    @pyqtSlot()
    def run(self):
        """Execute the worker function and emit appropriate signals.
        
        This method is called by QThreadPool when the worker is started.
        It executes the handle function with provided arguments and emits:
        - result signal with return value on success
        - error signal with exception info on failure
        - finished signal in all cases
        """
        try:
            result = self.handle(*self.args, **self.kwargs)
            self.signals.result.emit(result)
        except Exception:
            traceback.print_exc()
            exctype, value = sys.exc_info()[:2]
            self.signals.error.emit((exctype, value, traceback.format_exc()))
        finally:
            self.signals.finished.emit()
