# DEPENDENCY CHECK SUMMARY

Sums up OWASP dependency checks :

```sh
.summary.sh -f examples/dependency-check-report.json
```

## Requirements

- Python v3.9
- Poetry v1.1.12

You may need the following tools if not already installed :

* [OWASP Dependency Check](https://github.com/jeremylong/DependencyCheck/releases)

## Install

```sh
poetry install
```

## Usage

Run owasp-dependency-check from a java project :

```sh
dependency-check --project "ProjectName" --scan ./ --format JSON --prettyPrint
```

Run gosec from a Go project :

```sh

```

Parse the reports :

```sh
./summary --help
./summary
```

## Run Test

```sh
# run tests
pytest summary
```



Using poetry:

```sh
poetry run summary --help
```