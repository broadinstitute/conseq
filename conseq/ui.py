import logging

import signal
import contextlib

log = logging.getLogger(__name__)


@contextlib.contextmanager
def capture_sigint():
    "Context manager for handling ^C being pressed and delaying it until a convenient time to be handled synchronously"
    interrupted = [False]

    original_sigint = signal.getsignal(signal.SIGINT)

    def set_interrupted(signum, frame):
        signal.signal(signal.SIGINT, original_sigint)
        interrupted[0] = True
        log.warning("Interrupted!")

    signal.signal(signal.SIGINT, set_interrupted)

    yield lambda: interrupted[0]

    signal.signal(signal.SIGINT, original_sigint)


def ask_user(message, options, default=None):
    formatted_options = []
    for option in options:
        if option == default:
            option = f"[{default}]"
        formatted_options.append(option)
    formatted_options = "/".join(formatted_options)

    while True:
        answer = input("{} ({})? ".format(message, formatted_options))
        if answer == "" and default is not None:
            return default
        if answer in options:
            break
        print("Invalid input")

    return answer


def user_wants_reattach():
    return ask_user("Would you like to reattach existing jobs", ["y", "n"], "y") == "y"


def ask_user_to_cancel(j, executing):
    answer = ask_user(
        "Terminate {} running before exiting".format(len(executing)), ["y", "n"]
    )

    if answer == "y":
        for e in executing:
            e.cancel()


def ask_y_n(msg):
    while True:
        answer = input("{} (y/n): ".format(msg))
        if answer in ["y", "n"]:
            return answer == "y"
        print("Invalid input")


def user_says_we_should_stop(failure_count, executing):
    answer = ask_user(
        "Aborting due to failures {}, but there are {} jobs still running.  Terminate now".format(
            failure_count, len(executing)
        ),
        ["y", "n", "never"],
    )
    if answer == "y":
        return (True, failure_count)
    elif answer == "n":
        return (False, failure_count + 1)
    else:
        return (False, 1000000000)


def confirm_execution(transform, formatted_inputs):
    while True:
        answer = input(
            f"About to run {transform} on the following: {formatted_inputs}\nProceed to run {transform}? (y)es, (s)kip, (S)kip all, (a)lways or (q)uit: ".format()
        )
        if not (answer in ["y", "a", "q", "S", "s"]):
            print("Invalid input")
        return answer
