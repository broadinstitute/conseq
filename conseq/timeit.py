from contextlib import contextmanager
from time import time
from typing import Optional, Any


@contextmanager
def timeblock(log, label, min_time=0):
    start = time()
    try:
        yield
    finally:
        elapsed = time() - start
        if elapsed > min_time:
            log.info("timed block {}: {} seconds".format(label, elapsed))
