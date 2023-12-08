# This file exists to let you run "python -im"
# in your IDE with its nice debugger support
import runpy
from pathlib import Path
globals().update(runpy.run_module(Path(__file__).parent.name))
