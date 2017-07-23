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

#include "util.hpp"

namespace oride {

template <>
typename Gauss<uint64_t>::Noise Gauss<uint64_t>::fg_prng_sk(8.0, 128, 1 << 14);
template <>
typename Gauss<uint64_t>::Noise Gauss<uint64_t>::fg_prng_evk(8.0, 128, 1 << 14);
template <>
typename Gauss<uint64_t>::Noise Gauss<uint64_t>::fg_prng_pk(8.0, 128, 1 << 14);
template <>
typename Gauss<uint64_t>::Noise Gauss<uint64_t>::fg_prng_enc(8.0, 128, 1 << 14);


/** The following functions are taken from FV-NFLlib licensed under GPLv3 **/
/** See: https://github.com/CryptoExperts/FV-NFLlib/                      **/

namespace util {

/**
 * Center op1 modulo op2
 * @param rop     result
 * @param op1     number op1 already reduced modulo op2, i.e. such that 0 <= op1
 * < op2-1
 * @param op2     modulus
 * @param op2Div2 floor(modulus/2)
 */
void center(mpz_t &rop, mpz_t const &op1, mpz_t const &op2,
            mpz_t const &op2Div2) {
    mpz_set(rop, op1);
    if (mpz_cmp(op1, op2Div2) > 0)
        mpz_sub(rop, rop, op2);
}

/**
 * Compute the quotient of op1 divided by op2 for a centered noise
 * @param rop     result
 * @param op1     numerator
 * @param op2     denominator
 * @param op2Div2 floor(denominator/2)
 */
void div_and_round(mpz_t &rop, mpz_t const &op1, mpz_t const &op2,
                   mpz_t const &op2Div2) {
    mpz_t r;
    mpz_init2(r, mpz_size(op2) + 1);

    // Compute op1 = rop * op2 + r
    // where r has the same sign as op1
    mpz_tdiv_qr(rop, r, op1, op2);

    // Correct "rop" so that r is centered around 0
    long sgn = mpz_sgn(r);
    mpz_abs(r, r);
    if (mpz_cmp(r, op2Div2) >= 0) {
        if (sgn > 0)
            mpz_add_ui(rop, rop, 1);
        else
            mpz_sub_ui(rop, rop, 1);
    }

    // Clean
    mpz_clear(r);
}

}  // namespace util

}

