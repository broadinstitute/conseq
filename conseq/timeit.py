import collections
import threading
from contextlib import contextmanager
from functools import wraps
from time import time
from typing import Optional, Any

thread_locals = threading.local()

# map id -> stack
id_to_frame = {}
next_id = 1

# tuples of (entry_id, elapsed_time)
history = []

Frame = collections.namedtuple("Frame", "id children label parent")


# def _get_block_stack():
#     if hasattr(thread_locals, "block_stack"):
#         block_stack = thread_locals.block_stack
#     else:
#         block_stack = [Frame(0, {}, "start", None)]
#         thread_locals.block_stack = block_stack
#     return block_stack


# def _enter_frame(label):
#     global next_id

#     stack = _get_block_stack()
#     parent_frame = stack[0]
#     _, children_frames, parent_label, _ = parent_frame

#     frame = children_frames.get(label)
#     if frame is None:
#         id = next_id
#         next_id += 1
#         frame = (id, {}, label, parent_frame)
#         children_frames[label] = frame
#     else:
#         id = frame[0]
#     stack[0] = frame
#     return id


# def _exit_frame(frame_id, elapsed):
#     stack = _get_block_stack()
#     frame = stack[0]
#     id, children_frames, label, parent_frame = frame
#     assert frame_id == id
#     history.append((frame_id, elapsed))
#     stack[0] = parent_frame


def summarize_history():
    by_label = collections.defaultdict(lambda: [0, 0])
    for frame_id, elapsed in history:
        frame = id_to_frame[frame_id]
        rec = by_label[frame.label]
        rec[1] += elapsed
        rec[0] += 1
    return by_label


def timefn(log, label, parameter: Optional[Any] = None, min_time=0):
    def decorator(func):
        @wraps(func)
        def func_wrapper(*args, **kwargs):
            start = time()
            try:
                x = func(*args, **kwargs)
            finally:
                elapsed = time() - start
                if elapsed > min_time:
                    if parameter is not None:
                        label_ = f"{label}({args[parameter]})"
                    else:
                        label_ = label
                    log.info(f"timed {label_}: {elapsed} seconds")
            return x

        return func_wrapper

    return decorator


@contextmanager
def timeblock(log, label, min_time=0):
    start = time()
    try:
        yield
    finally:
        elapsed = time() - start
        if elapsed > min_time:
            log.info("timed block {}: {} seconds".format(label, elapsed))
