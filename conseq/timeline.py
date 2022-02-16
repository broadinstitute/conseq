import random
import string
import csv
import datetime
# def _datetimefromiso(isostr):
#     return datetime.datetime.strptime(isostr, "%Y-%m-%dT%H:%M:%S.%f")
import os

class TimelineLog:
    def __init__(self, filename: str) -> None:
        if filename is not None:
            is_new = not os.path.exists(filename)
            self.fd = open(filename, "at")
            self.w = csv.writer(self.fd)
            self.batch_id = "".join([ random.choice(string.ascii_letters) for x in range(5) ])
            if is_new:
                self.w.writerow(["timestamp", "batchid", "jobid", "label", "status"])
            self.log("", "batch", "start")

        else:
            self.fd = None
            self.w = None

    def log(self, job_id: int, label: str, status: str) -> None:
        if self.fd is None:
            return
        self.w.writerow([datetime.datetime.now().isoformat(), self.batch_id, job_id, label, status])
        self.fd.flush()

    def close(self):
        self.log("", "batch", "end")
        self.fd.close()
        self.fd = None
        self.w = None
