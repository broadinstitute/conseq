import json

__version__ = '1.22.0'


def Local(name):
    return {"$filename": name}


def Varies(value):
    return {"$value": value}


def LocalP(name):
    return {"name": name, "filename": Local(name)}


def publish(*items):
    with open("results.json", "w") as fd:
        json.dump({"outputs": items}, fd)
