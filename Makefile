.PHONY: build clean

PYTHON ?= /usr/bin/env python3

pts: passthesalt/*.py
	zip --quiet pts passthesalt/*.py
	zip --quiet --junk-paths pts passthesalt/__main__.py
	echo '#!$(PYTHON)' > pts
	cat pts.zip >> pts
	rm pts.zip
	chmod a+x pts

build:
	virtualenv --python=python3 venv
	venv/bin/pip install -e .

clean:
	rm pts
