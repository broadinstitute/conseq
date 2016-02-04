import json, os

def Local(name):
    return {"$filename": name}

def LocalP(name):
    return {"name": name, "filename": Local(name)}

def publish(*items):
    with open("results.json", "w") as fd:
        json.dump({"outputs":items}, fd)

