"""Catch typed resource failures while loading or running the owned debugger launcher.

Only this package's fixed sibling is executed; caller input stays in request.json.
Interpreter startup failures before this boundary remain unclassified.
"""
import errno
import os
import runpy
import sys


def resource_exit(status, marker):
    try:
        if len(sys.argv) > 2:
            descriptor = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.write(descriptor, marker)
            os.close(descriptor)
    except (OSError, MemoryError):
        # Without a complete marker the parent keeps this failure unclassified.
        pass
    os._exit(status)

try:
    # Run by path: `python -I` keeps this directory off sys.path, so the
    # sibling cannot be imported, and loading it here keeps its import-time
    # allocation failures inside this classification boundary.
    runpy.run_path(
        os.path.join(os.path.dirname(__file__), "launch_impl.py"), run_name="__main__"
    )
except MemoryError:
    # Reserved status: an observed allocation failure, including imports/compile.
    resource_exit(75, b"M")
except OSError as error:
    # ENOMEM is an observed allocation failure, independent of error text.
    if error.errno == errno.ENOMEM:
        resource_exit(75, b"M")
    # EFBIG is observed directly, including a partial limits/reply write.
    if error.errno == errno.EFBIG:
        resource_exit(76, b"F")
    raise
