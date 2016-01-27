import dep

assert dep.Obj(None, (("name", "a"),)).is_instance_of(dep.Obj(None, (("name", "a"),)))
assert dep.Obj(None, (("name", "a"),("extra", "b"))).is_instance_of(dep.Obj(None, (("name", "a"),)))
assert not dep.Obj(None, (("name", "a"),)).is_instance_of(dep.Obj(None, (("name", "a"),("extra", "b"))))
