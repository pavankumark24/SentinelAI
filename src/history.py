import json
import os
from datetime import datetime

FILE_PATH = "scan_history.json"


def save_scan(score, severity):

    history = []

    if os.path.exists(FILE_PATH):

        try:

            with open(FILE_PATH, "r") as f:
                history = json.load(f)

        except:
            history = []

    history.append({
        "timestamp": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "score": score,
        "severity": severity
    })

    with open(FILE_PATH, "w") as f:

        json.dump(
            history,
            f,
            indent=4
        )


def load_history():

    if not os.path.exists(FILE_PATH):
        return []

    try:

        with open(FILE_PATH, "r") as f:
            return json.load(f)

    except:

        return []