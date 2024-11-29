SHELL := /bin/bash
.ONESHELL:

.PHONY: init test coverage clean

init:
	python3.9 -m venv venv
	. venv/bin/activate
	pip install --upgrade pip
	pip install -r requirements-dev.txt

test:
	. venv/bin/activate
	pytest tests/

coverage:
	. venv/bin/activate
	pytest --cov=./ --cov-report=term --cov-report=html tests/

clean:
	rm -rf venv
	rm -rf __pycache__
	rm -rf tests/__pycache__
	rm -rf htmlcov
