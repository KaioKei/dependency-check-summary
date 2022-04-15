import json
from pathlib import Path
from typing import Dict

from summary.lib.exceptions.file_exceptions import NotAJsonFormat


def read_json(file: Path) -> Dict:
    with open(file, 'r') as f:
        try:
            return json.load(f)
        except ValueError:
            raise NotAJsonFormat(file)
