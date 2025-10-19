PYTHON_INCLUDE := $(shell python3 -c "import sysconfig; print(sysconfig.get_path('include'))")
HS_FLAGS := $(shell pkg-config --cflags --libs libhs)

.PHONY: test
test:
	PYTHONPATH=. pytest tests/ -v

.PHONY: compile
compile: hscheck.so

hscheck.so: hscheck.c
	gcc -shared -fPIC -o hscheck.so hscheck.c -I$(PYTHON_INCLUDE) $(HS_FLAGS)
