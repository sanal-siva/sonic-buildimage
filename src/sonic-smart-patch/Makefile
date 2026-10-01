.PHONY: all sonic-smart-patch deb test clean
all: sonic-smart-patch
sonic-smart-patch: deb
deb:
	python3 scripts/build-deb.py

test:
	PYTHONPATH=. python3 -m unittest discover -s tests -p 'test_*.py'

clean:
	rm -rf build dist sonic_smart_patch.egg-info
