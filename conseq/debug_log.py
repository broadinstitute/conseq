import hashlib
import json
import time

_LOG_HANDLE = None


def _hash(s):
    return hashlib.md5(s.encode("utf8")).hexdigest()


def _log(record):
    global _LOG_HANDLE
    record["timestamp"] = time.asctime(time.localtime())
    if _LOG_HANDLE is None:
        _LOG_HANDLE = open("conseq-debug.log", "at")
    _LOG_HANDLE.write(json.dumps(record) + "\n")
    _LOG_HANDLE.flush()


def log_execute(name, id, job_dir, inputs, run_stmts):
    _log(
        dict(
            type="execute",
            name=name,
            id=id,
            job_dir=job_dir,
            inputs=[repr(i) for i in inputs],
            run_stmts=run_stmts,
            run_stmts_hash=_hash(repr(run_stmts)),
        )
    )


def log_input_preprocess(id, orig_inputs, processed_inputs):
    _log(
        dict(
            type="preprocess",
            id=id,
            orig_inputs=[repr(i) for i in orig_inputs],
            processed_inputs=processed_inputs,
        )
    )


def log_completed(id, status, outputs):
    _log(dict(type="completed", id=id, status=status, outputs=outputs))


def log_pullmap(mapping):
    _log(dict(type="mapping", mapping=mapping))
