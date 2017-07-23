/*
 * ORide: A Privacy-Preserving yet Accountable Ride-Hailing Service
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see http://www.gnu.org/licenses/gpl-3.0.txt
 */

#include "tests.hpp"

#include "fv.hpp"
#include "stats.hpp"
#include <chrono>

using namespace oride;

// A simple test of the protocol with one rider and one driver.
template <typename T, size_t Degree, size_t NbModuli, typename U>
void test_simple_impl(int count)
{
    using SK = SecretKey<T, Degree, NbModuli>;
    using APK = AbstractPublicKey<T, Degree, NbModuli>;
    using PK = PublicKey<T, Degree, NbModuli>;

    using PT = Plaintext<U, Degree>;
    using CT2 = Ciphertext2<T, Degree, NbModuli, U>;
    using CT3 = Ciphertext3<T, Degree, NbModuli, U>;

    print_params<T, Degree, NbModuli, U>();

    // Objects to gather benchmark statistics.
    Stats genkeys;
    Stats pubkey;
    Stats enc;
    Stats eval;
    Stats dec;

    // Non-cryptographic PRNG to generate the rider's and driver's locations.
    // Each coordinate is an integer between 0 and 2^k-1, for some bitlength k.
    std::default_random_engine generator;
    //std::uniform_int_distribution<U> distribution(0, (1<<14) - 1);
    std::uniform_int_distribution<U> distribution(0, (1<<9) - 1);
    std::array<U, Degree> a, b, c, d;

    // Initialize null plaintexts.
    for (size_t i = 0 ; i < Degree ; ++i)
    {
        a[i] = 0;
        b[i] = 0;
        c[i] = 0;
        d[i] = 0;
    }

    for (int i = 0 ; i < count ; ++i)
    {
        // Generate rider's and driver's locations.
        a[0] = distribution(generator);
        b[0] = distribution(generator);
        c[0] = distribution(generator);
        d[0] = distribution(generator);

        // Rider generates a key pair.
        auto t0_genkeys = std::chrono::high_resolution_clock::now();
        SK sk;
        APK apk(sk);
        auto t1_genkeys = std::chrono::high_resolution_clock::now();

        // Driver loads the public key (also does some NTT precomputation).
        auto t0_pubkey = std::chrono::high_resolution_clock::now();
        PK pk(std::move(apk));
        auto t1_pubkey = std::chrono::high_resolution_clock::now();

        // Rider encrypts her location.
        auto t2_enc = std::chrono::high_resolution_clock::now();
        PT rx(a);
        PT ry(b);
        CT2 erx = pk.encrypt(rx);
        CT2 ery = pk.encrypt(ry);
        auto t3_enc = std::chrono::high_resolution_clock::now();

        // Driver encrypts her location.
        auto t0_enc = std::chrono::high_resolution_clock::now();
        PT dx(c);
        PT dy(d);
        CT2 edx = pk.encrypt(dx);
        CT2 edy = pk.encrypt(dy);
        auto t1_enc = std::chrono::high_resolution_clock::now();

        // Service provider homomorphically computes the squared Euclidean
        // distance.
        auto t0_eval = std::chrono::high_resolution_clock::now();
        erx -= edx;
        ery -= edy;
        CT3 erx2 = erx.mul_norelin(erx);
        CT3 ery2 = ery.mul_norelin(ery);
        erx2 += ery2;
        auto t1_eval = std::chrono::high_resolution_clock::now();

        // Rider decrypts.
        auto t0_dec = std::chrono::high_resolution_clock::now();
        rx = sk.decrypt(erx2);
        auto t1_dec = std::chrono::high_resolution_clock::now();

        // We check that decryption is consistent.
        for (size_t i = 0 ; i < Degree ; ++i)
        {
            auto dx = a[i] - c[i];
            auto dy = b[i] - d[i];
            auto d2 = dx*dx + dy*dy;
            if (rx.get(i) != d2)
            {
                std::cerr << "Error at index " << i << " : {" << a[i] << ", " << b[i] << "}, {" << c[i] << ", " << d[i] << "} -> " << d2 << " - " << rx.get(i) << " = " << int(d2 - rx.get(i)) << std::endl;
                std::cerr << "Not testing for further errors" << std::endl;
                break;
            }
        }

        // Update benchmark statistics.
        genkeys.add(std::chrono::duration_cast<std::chrono::microseconds>(t1_genkeys - t0_genkeys).count());
        pubkey.add(std::chrono::duration_cast<std::chrono::microseconds>(t1_pubkey - t0_pubkey).count());
        enc.add(std::chrono::duration_cast<std::chrono::microseconds>(t3_enc - t2_enc).count());
        enc.add(std::chrono::duration_cast<std::chrono::microseconds>(t1_enc - t0_enc).count());
        eval.add(std::chrono::duration_cast<std::chrono::microseconds>(t1_eval - t0_eval).count());
        dec.add(std::chrono::duration_cast<std::chrono::microseconds>(t1_dec - t0_dec).count());
    }

    // Print statistics.
    std::cerr << "Generate keys : " << genkeys << " us" << std::endl;
    std::cerr << "Public key shoup : " << pubkey << " us" << std::endl;
    std::cerr << "Encrypt : " << enc << " us/point" << std::endl;
    std::cerr << "Eval : " << eval << " us/driver" << std::endl;
    std::cerr << "Decrypt : " << dec << " us/distance" << std::endl;
}


void test_simple()
{
    // Loop 'count' times through the whole benchmark.
    int count = 1000;
    test_simple_impl<uint64_t, 4096, 2, uint32_t>(count);
}

int main()
{
    std::cerr << "******************** Simple algo ********************" << std::endl;
    test_simple();
    return 0;
}

