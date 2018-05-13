def indent_str(s, depth):
    pad = " " * depth
    return "\n".join([pad + x for x in s.split("\n")])
