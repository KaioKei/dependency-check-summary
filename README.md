# DEPENDENCY CHECK SUMMARY

Sums up dependency scanner reports.

Dependency Check Summary supports :

* [OWASP Dependency Check reports](https://github.com/jeremylong/DependencyCheck/releases)
* [Gosec reports](https://github.com/securego/gosec)

## Requirements

- Python v3.9
- Poetry v1.1.12

## Install

```sh
poetry install
```

## Quick Start

```sh
summary.sh -f examples/dependency-check-report.json -t owasp-dependency-check
```

## Usage

Run a vulnerability scan :

```sh
# owasp-dependency-check from a java project
dependency-check --project "ProjectName" --scan ./ --format JSON --prettyPrint -o /tmp/report.json
# gosec from a go project
gosec -fmt=json -out=/tmp/report.json *.go
```

Parse the reports :

```sh
# for owasp-dependency-check report
summary.sh -f /tmp/report.json -t owasp-dependency-check
# for gosec report
summary.sh -f /tmp/report.json -t gosec
```

## Run Tests

```sh
# run tests
poetry run pytest --cov=summary summary
```