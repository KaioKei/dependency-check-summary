from pathlib import Path


class JsonFileFormatException(Exception):
    def __init__(self, file: Path):
        self.file = file

    def __str__(self):
        return f"Error in JSON file: {self.file}"


class NotAJsonFormat(JsonFileFormatException):
    def __init__(self, file: Path):
        super().__init__(file)

    def __str__(self):
        return f"Not a JSON file: {self.file}"
