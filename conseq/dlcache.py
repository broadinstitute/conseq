import sqlite3
import os

class Cache:
    def __init__(self, db):
        self.db = db
    def get(self, url):
        c = self.db.cursor()
        c.execute("select local_path from entry where url = ?", [url])
        row = c.fetchone()
        c.close()
        if row == None:
            return None
        else:
            return row[0]

    def set(self, url, dest):
        c = self.db.cursor()
        c.execute("insert into entry (url, local_path) values (?, ?)", [url, dest])
        c.close()
        self.db.commit()

def open_dl_db(filename):
    needs_create = not os.path.exists(filename)

    db = sqlite3.connect(filename)

    if needs_create:
        stmts = ["create table entry (id INTEGER PRIMARY KEY   AUTOINCREMENT, url STRING, local_path STRING)"]
        for stmt in stmts:
            db.execute(stmt)

    return db
