from typing import Set, Union, Tuple
from collections import defaultdict
import re

EACH="each"
ALL="all"

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
            return (type == EACH and each) or (type == ALL and all)

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
    # import pdb
    # pdb.set_trace()
    for successor in graph.get_successors(name, each=True, all=False):
        next_steps.add(successor)

    if is_fully_complete(graph, completed, in_progress, name):
        # if name is complete, then update completed and call get_full_completions to see if there's something new that
        # we also know has completed given that 'name' has completed
        completed.add(name)
        # all the "all" relationship children are now up for evaluation after "name" is done
        for successor in graph.get_successors(name, each=False, all=True):
            next_steps.add(successor)

        # # now, traverse all the "all" properties downstream until
        # while True:
        #     new_completions = get_full_completions(graph, completed, in_progress, name)
        #     if len(new_completions) == 0:
        #         break
        #
        #     assert len(new_completions.intersection(completed)) == 0, "get_full_completions reported a rule as newly completed, but it was already marked completed"
        #
        #     # all the newly complete can
        #     for name_ in new_completions:
        #         for successor in graph.get_successors(name_, each=False, all=True):
        #             next_steps.add(successor)
        #
        #     completed.update(new_completions)

    return completed, next_steps

def verify_sequence(productions, steps):
    completed = set()
    in_progress_count = defaultdict(lambda: 0)
    graph = parse_graph(productions)
    prev_next_steps = None

    for starts, stop, expected_next in steps:
        print(f"starts: {starts}, stop: {stop}")
        starts = starts.split(" ")
        #expected_next = expected_next.split(" ")

        for start in starts:
            if start == "":
                continue

            if prev_next_steps is not None:
                assert start in prev_next_steps
            in_progress_count[start] += 1
        print(f"after starts in_progress_count: {in_progress_count}")

        if stop != "":
            in_progress_count[stop] -= 1
        print(f"after stop in_progress_count: {in_progress_count}")

        in_progress = {name for name, count in in_progress_count.items() if count > 0}
        completed, next_steps = get_next_steps(graph, completed, in_progress, stop)

        print(f"completed: {completed}, next_steps: {next_steps}, expected: {expected_next}")

        assert expected_next == " ".join(sorted(next_steps))
        prev_next_steps = next_steps

def parse_graph(productions):
    edges = []
    for p in productions.split("\n"):
        p = p.strip()
        if p == "":
            continue
        m = re.match(r"(\*?)(\w+)->(\w+)", p)
        assert m
        type = ALL if m.group(1) == "*" else EACH
        parent = m.group(2)
        child = m.group(3)
        edges.append((parent, child, type))
    return Graph(edges)

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
        [("a", "a", "b"), ("b b", "b", "c"), ("c", "b", "c"), ("", "c", "")])

def test_fork():
    verify_sequence(
        """
        a->b
        b->c
        b->d
        """,
        [("a", "a", "b"), ("b", "b", "c d"), ("c d", "c", ""), ("", "d", "")])

def test_join():
    verify_sequence(
        """
        a->c
        b->c
        c->d
        """,
        [("a b", "a", "c"), ("", "b", "c"), ("c", "c", "d"), ("d", "d", "")])

def test_chain_with_all():
    verify_sequence(
    """
    a->b
    *b->c
    """,
    [("a", "a", "b"), ("b", "b", "c"), ("c", "c", "")])

    verify_sequence(
    """
    a->b
    *b->c
    """,
    [("a", "a", "b"), ("b b", "b", ""), ("", "b", "c"), ("c", "c", "")])
