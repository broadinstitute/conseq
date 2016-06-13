# an installable handler for dumping traceback on SIGQUIT based on http://stackoverflow.com/questions/132058/showing-the-stack-trace-from-a-running-python-application
import threading, traceback, signal, sys

def dump_trace(sig, frame):
    id2name = dict([(th.ident, th.name) for th in threading.enumerate()])
    code = []
    for threadId, stack in sys._current_frames().items():
        code.append("\n# Thread: %s(%d)" % (id2name.get(threadId,""), threadId))
        for filename, lineno, name, line in traceback.extract_stack(stack):
            code.append('File: "%s", line %d, in %s' % (filename, lineno, name))
            if line:
                code.append("  %s" % (line.strip()))
    sys.stderr.write("".join([x+"\n" for x in code]))
    sys.stderr.flush()

def install():
    signal.signal(signal.SIGQUIT, dump_trace)  # Register handler
