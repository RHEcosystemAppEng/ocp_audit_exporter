include Makefile.common

.PHONY: all test clean
.DEFAULT_GOAL: build


all: build

test: unit_tests

clean: clean_go
