import random
import string
import csv
import datetime
from typing import Optional
import os


class TimelineLog:
    def __init__(self, filename: str) -> None:
        if filename is not None:
            is_new = not os.path.exists(filename)
            self.fd = open(filename, "at")
            self.w = csv.writer(self.fd)
            self.batch_id = "".join(
                [random.choice(string.ascii_letters) for x in range(5)]
            )
            if is_new:
                self.w.writerow(["timestamp", "batchid", "jobid", "label", "status"])
            self.log(None, "batch", "start")

        else:
            self.fd = None
            self.w = None

    def log(self, job_id: Optional[int], label: str, status: str) -> None:
        if self.fd is None:
            return
        if job_id is None:
            job_id_str = ""
        else:
            job_id_str = str(job_id)
        assert self.w is not None
        self.w.writerow(
            [
                datetime.datetime.now().isoformat(),
                self.batch_id,
                job_id_str,
                label,
                status,
            ]
        )
        self.fd.flush()

    def close(self):
        assert self.fd is not None
        self.log(None, "batch", "end")
        self.fd.close()
        self.fd = None
        self.w = None
