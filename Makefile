
all:
	cd NFLlib/ && rm -Rf _build/ && mkdir _build && cd _build/ && cmake .. && make
	cd src/    && rm -Rf _build/ && mkdir _build && cd _build/ && cmake .. && make
	mkdir -p benchmarks
	ln -sf ../src/_build/test_simple benchmarks/

bench: benchmarks/test_simple
	benchmarks/test_simple

clean:
	rm -Rf NFLlib/_build/ src/_build/ benchmarks/

