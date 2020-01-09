import hashlib
import os
import shelve


def sha256_from_file(filename):
    h = hashlib.sha256()
    with open(filename, "rb") as fd:
        for chunk in iter(lambda: fd.read(100000), b""):
            h.update(chunk)
    return h.hexdigest()


class HashCache:
    def __init__(self, cache_path):
        self.cache_path = cache_path

    def sha256(self, filename):
        filename = os.path.abspath(filename)
        mtime = os.path.getmtime(filename)
        key = "path={},mtime={}".format(filename, mtime)
        with shelve.open(self.cache_path) as cache:
            sha256 = cache.get(key)
            if sha256 is None:
                sha256 = sha256_from_file(filename)
            cache[key] = sha256
        return sha256
