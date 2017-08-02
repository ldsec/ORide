
all:
	cd NFLlib/ && rm -Rf _build/ && mkdir _build && cd _build/ && cmake .. && make
	cd src/    && rm -Rf _build/ && mkdir _build && cd _build/ && cmake .. && make
	mkdir -p benchmarks
	ln -sf ../src/_build/test_simple benchmarks/
	ln -sf ../src/_build/test_honest benchmarks/
	ln -sf ../src/_build/test_oride benchmarks/

bench: benchmarks/test_simple benchmarks/test_honest benchmarks/test_oride
	benchmarks/test_simple
	benchmarks/test_honest
	benchmarks/test_oride

clean:
	rm -Rf NFLlib/_build/ src/_build/ benchmarks/

