.PHONY: test smoke package

test:
	python3 -m py_compile privscope.py
	python3 -m unittest discover -s tests -v

smoke:
	python3 privscope.py --checks context,path,kernel --format json --fail-on never >/tmp/privscope-smoke.json
	python3 -m json.tool /tmp/privscope-smoke.json >/dev/null

package: test
	cd .. && zip -r privscope.zip privscope -x 'privscope/__pycache__/*' 'privscope/tests/__pycache__/*'
