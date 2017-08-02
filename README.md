# ORide
ORide: A Privacy-Preserving yet Accountable Ride-Hailing Service

Ride-hailing services (RHSs), such as Uber and Lyft, enable millions of riders and drivers worldwide to set up rides via their smartphones. Their advantage over traditional taxi services is due to the convenience of their services, e.g., ride requests at the touch of a button, fare estimation, automatic payments, and reputation ratings. To offer such services, however, RHSs collect a vast amount of sensitive information that puts at risk the privacy of riders and drivers. As a result, a RHS or any entity with access to this data, can infer sensitive information about riders’ and drivers’ activities.
We propose ORide (Oblivious Ride), a privacy-friendly RHS designed to support all the key features of current RHSs while significantly reducing the sensitive information it collects. ORide relies on novel cryptographic techniques (e.g., somewhat-homomorphic encryption or SHE) and optimizations to enable a RHS to efficiently match riders and drivers without learning their identities and their location information. Notably, ORide offers robust privacy guarantees while still supporting key RHS features such as easy payment, reputation scores, accountability and retrieval of lost items. In addition, our thorough performance evaluation shows that ORide introduces acceptable computational, network, and operational overheads. For example, ORide adds only several milliseconds to ride-hailing operations.

## Structure of the code

This project is organized as follows.

- `NFLlib/`: ORide uses [NFLlib](https://github.com/quarkslab/NFLlib) for cryptographic operations on lattices (GPLv3 license). We include it with minor fixes in this folder.
In particular, we use 20-bit plaintexts for `uint32_t`, to obtain correct results given the amount of homomorphic computation.
- `src/`: Source code for our ride matching proof-of-concept, with benchmarks and examples.
- `src/test_simple.cpp`: A simple version of the protocol with only one rider and one driver, to get familiar with the cryptographic operations.
- `src/fv.hpp`: Implementation of the FV homomorphic encryption scheme, inspired from [FV-NFLlib](https://github.com/CryptoExperts/FV-NFLlib) (licensed under GPLv3).
- `src/util.hpp`: Misc operations on lattices for FV.
- `src/serialize.hpp`: Serialize cryptographic keys and ciphertexts to/from byte sequences.
- `src/stats.hpp`: Class to gather benchmark statistics (mean, variance, median).
- `scripts/ntt-params.sage`: [Sage](http://www.sagemath.org/) script to generate NTT parameters for various plaintext sizes.

## Running the benchmarks

Make sure to have a C++11 compiler and CMake (version >= 2.8.1).
To create the benchmark programs, run `make`.
Then, run `make bench` to launch them.

## LICENSE

GPLv3

Part of the code is derived from source code of the following projects (licensed under GPLv3):
- [NFLlib](https://github.com/quarkslab/NFLlib)
- [FV-NFLlib](https://github.com/CryptoExperts/FV-NFLlib)

