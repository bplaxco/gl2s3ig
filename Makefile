.PHONY: test
test:
	PYTHONPATH=. pytest tests/ -v
