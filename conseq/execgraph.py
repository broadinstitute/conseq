from typing import Set, Union, Tuple

class Graph:
    def __init__(self, edges):
        self.precursors = defaultdict(lambda: set())
        self.successors = defaultdict(lambda : set())

        for parent, child, type in edges:
            self.precursors[child].add(parent)
            self.successors[parent].add((child, type))

    def get_precursors(self, name):
        return self.precursors[name]

    def get_successors(self, name, each=True, all=True):
        def ok(type):
            return (type == "each" and each) or (type == "all" and all)

        return { child for child, type in self.successors[name] if ok(type) }

def is_fully_complete(graph: Graph, completed : Set[str], in_progress: Set[str], name : str) -> bool :
    if name in in_progress:
        return False

    for precursor in graph.get_precursors(name):
        if precursor not in completed:
            return False

    return True


def get_full_completions(graph: Graph, completed : Set[str], in_progress: Set[str], name: str):
    new_completions = set()
    for successor in graph.get_successors(name, each=True, all=True):
        if is_fully_complete(graph, completed, in_progress, successor):
            new_completions.add(successor)

    return new_completions

def get_next_steps(graph : Graph, completed : Set[str], in_progress: Set[str], name: str) -> Tuple[Set[str], Set[str]]:
    next_steps = set()
    completed = set(completed)

    for successor in graph.get_successors(name, each=True, all=False):
        next_steps.add(successor)

    if is_fully_complete(graph, completed, in_progress, name):
        completed.add(name)
        while True:
            new_completions = get_full_completions(graph, completed, in_progress, name)
            if len(new_completions) == 0:
                break

            for name_ in new_completions:
                for successor in graph.get_successors(name_, each=False, all=True):
                    next_steps.add(successor)

            completed.update(new_completions)

    return completed, next_steps

from collections import defaultdict
def verify_sequence(productions, steps):
    in_progress_count = defaultdict(lambda: 0)
    graph = parse_graph(productions)
    prev_next_steps = None
    for starts, stop, expected_next in steps:
        starts = starts.split(" ")
        expected_next = expected_next.split(" ")

        for start in starts:
            if prev_next_steps is not None:
                assert start in prev_next_steps
            in_progress_count[start] += 1

        in_progress_count[stop] -= 1
        in_progress = {name for name, count in in_progress_count.items() if count > 0}
        completed, next_steps = get_next_steps(graph, completed, in_progress, stop)

        assert expected_next == " ".join(sorted(next_steps))
        prev_next_steps = next_steps

def test_simple_chain():
    verify_sequence(
        """
        a->b
        b->c
        """,
        [("a", "a", "b"), ("b", "b", "c"), ("c", "c", "")])

def test_chain_with_multiple_b():
    verify_sequence(
        """
        a->b
        b->c
        """,
        [("a", "b"), ("b", "c"), ("b", "c"), ("c", ""), ("c", "")])

def test_fork():
    verify_sequence(
        """
        a->b
        b->c
        b->d
        """,
        [("a", "b"), ("b", "c d"), ("c", ""), ("d", "")])

def test_join():
    verify_sequence(
        """
        a->c
        b->c
        c->d
        """,
        [("a", "c"), ("b", "c"), ("c", "d"), ("d", "")])

def test_chain_with_all():
    verify_sequence(
    """
    a->b
    *b->c
    """,
    [("a", "b"), ("b", "c"), ("c", "")])

    verify_sequence(
    """
    a->b
    *b->c
    """,
    [("a", "b"), ("a", "b"), ("b", "c"), ("c", "")])
