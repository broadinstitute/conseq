from time import time
from functools import wraps
from contextlib import contextmanager

def timefn(label, parameter=None):
    def decorator(func):
        @wraps(func)
        def func_wrapper(*args, **kwargs):
            start = time()
            try:
                x = func(*args, **kwargs)
            finally:
                elapsed = time() - start
                if parameter is not None:
                    label = "{}({})".format(label, args[parameter])
                print("timed {}: {} seconds".format(label, elapsed))
            return x
        return func_wrapper
    return decorator

@contextmanager
def timeblock(label):
    start = time()
    try:
        yield
    finally:
        elapsed = time() - start
        print("timed {}: {} seconds".format(label, elapsed))
