from pathlib import Path
import sys

import siem_web

log_path = Path(__file__).with_name("server.run.log")
log_file = log_path.open("a", encoding="utf-8", buffering=1)
sys.stdout = log_file
sys.stderr = log_file

siem_web.main()
