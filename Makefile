PY ?= python

.PHONY: install dev sample demo test lint format docker clean

install:        ## install the tool (adds the `nti` command)
	$(PY) -m pip install .

dev:            ## editable install + dev tools + git hooks
	$(PY) -m pip install -e ".[dev]"
	pre-commit install

sample:         ## generate the synthetic incident capture
	$(PY) tools/generate_sample_pcap.py -o samples/sample_incident.pcap

demo: sample    ## regenerate the committed DEMO-001 report set
	$(PY) -m nti samples/sample_incident.pcap --case-id DEMO-001 --analyst "SOC Team" -o reports

test:           ## run the test suite with coverage
	$(PY) -m pytest --cov --cov-report=term-missing

lint:
	ruff check .
	ruff format --check .

format:
	ruff check --fix .
	ruff format .

docker:
	docker build -t nti .

clean:
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache .coverage
