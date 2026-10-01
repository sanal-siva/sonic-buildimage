.PHONY: all sonic-guardian deb test clean
all: sonic-guardian
sonic-guardian: deb
deb:
	python3 scripts/build-deb.py

test:
	PYTHONPATH=. python3 -m unittest discover -s tests -p 'test_*.py'

clean:
	rm -rf build dist sonic_guardian.egg-info
