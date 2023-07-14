import sqlite3
import os

# from dep import Jobs
from contextlib import contextmanager
import sqlite3
import threading
from sqlite3 import Connection, Cursor
from typing import Iterable, Iterator


def prepare_db_connection(filename: str):
    needs_create = not os.path.exists(filename)

    db = sqlite3.connect(filename)
    # enforce FK constraints
    db.execute("PRAGMA foreign_keys = ON")

    stmts = []
    if needs_create:
        stmts.extend(
            [
                "create table rule (id INTEGER PRIMARY KEY AUTOINCREMENT, transform STRING, key STRING)",
                "create table cur_obj (id INTEGER PRIMARY KEY AUTOINCREMENT, space string, timestamp STRING, json STRING)",
                "create table past_obj (id INTEGER PRIMARY KEY AUTOINCREMENT, space string, timestamp STRING, json STRING)",
                "create table execution (id INTEGER PRIMARY KEY AUTOINCREMENT, transform STRING, status STRING, execution_xref STRING, job_dir STRING)",
                "create table execution_input (id INTEGER PRIMARY KEY AUTOINCREMENT, execution_id INTEGER, name STRING, obj_id INTEGER, is_list INTEGER)",
                "create table execution_output (id INTEGER PRIMARY KEY AUTOINCREMENT, execution_id INTEGER, obj_id INTEGER)",
                "create table rule_execution (id INTEGER PRIMARY KEY AUTOINCREMENT, space STRING, transform STRING, key STRING, state STRING, execution_id integer,"
                "FOREIGN KEY(execution_id) REFERENCES execution(id))",
                "create table rule_execution_input (id INTEGER PRIMARY KEY AUTOINCREMENT, rule_execution_id INTEGER, name STRING, obj_id INTEGER, is_list INTEGER)",
                "create table settings (schema_version integer, default_space string)",
                "insert into settings (schema_version, default_space) values (3, 'public')",
                "create table space (name string, parent string)",
                "insert into space (name) values ('public')",
                "create table rule_snapshot (transform STRING PRIMARY KEY, definition string)",
                "create table type_def (name string primary key, definition_json string)",
            ]
        )
    else:
        c = db.cursor()
        try:
            c.execute("SELECT schema_version FROM settings")
            schema_version = c.fetchone()[0]
        except sqlite3.OperationalError:
            schema_version = 0
        c.close()

        if schema_version < 1:
            stmts.extend(
                [
                    "create table settings (schema_version integer, default_space string)",
                    "insert into settings (schema_version, default_space) values (1, 'public')",
                    "create table space (name string, parent string)",
                    "insert into space (name) values ('public')",
                ]
            )
        if schema_version < 2:
            stmts.extend(
                [
                    "update settings set schema_version = 2",
                    "create table rule_snapshot (transform string, definition string)",
                ]
            )
        if schema_version < 3:
            stmts.extend(
                [
                    "update settings set schema_version = 3",
                    "create table type_def (name string primary key, definition_json string)",
                ]
            )

    for stmt in stmts:
        db.execute(stmt)

    return db


current_db_cursor_state = threading.local()


@contextmanager
def transaction(db: Connection) -> Iterator:
    cursor = None
    depth = 0
    if hasattr(current_db_cursor_state, "cursor"):
        cursor = current_db_cursor_state.cursor
        depth = current_db_cursor_state.depth
    if cursor == None:
        cursor = db.cursor()
        current_db_cursor_state.cursor = cursor
    depth += 1
    current_db_cursor_state.depth = depth
    try:
        yield
    finally:
        current_db_cursor_state.depth -= 1
        if current_db_cursor_state.depth == 0:
            current_db_cursor_state.cursor.close()
            current_db_cursor_state.cursor = None
            db.commit()


def get_cursor() -> Cursor:
    assert current_db_cursor_state.cursor != None
    return current_db_cursor_state.cursor
