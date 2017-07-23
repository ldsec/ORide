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

#ifndef ORIDE__UTIL_HPP
#define ORIDE__UTIL_HPP

#include <nfl.hpp>

namespace oride {

template <typename T>
class Gauss
{
public:
    using Struct = nfl::gaussian<uint16_t, T, 2>;
    using Noise = nfl::FastGaussianNoise<uint16_t, T, 2>;

    static Noise fg_prng_sk;
    static Noise fg_prng_evk;
    static Noise fg_prng_pk;
    static Noise fg_prng_enc;
};


template <typename T, size_t Degree, size_t NbModuli>
using Poly = nfl::poly_p<T, Degree, NbModuli>;

template <typename T, size_t Degree, size_t NbModuli>
using PolyZ = nfl::poly_p<T, Degree, 2*NbModuli + 1>;


template <typename T, size_t Degree, size_t NbModuli>
class ParamsCT
{
public:
    static constexpr size_t N = Degree * NbModuli;
    static constexpr size_t Nbytes = N * sizeof(T);
    using P = Poly<T, Degree, NbModuli>;
    using PZ = PolyZ<T, Degree, NbModuli>;

    static ParamsCT p;

    inline size_t log2q() {generate(); return _log2q;}
    inline const mpz_t& qDivBy2() {generate(); return _qDivBy2;}
    inline const mpz_t& bigmodDivBy2() {generate(); return _bigmodDivBy2;}

    static constexpr size_t bytesPublicKey = 2*Nbytes;
    static constexpr size_t bytesCiphertext = 2*Nbytes;

private:
    ParamsCT();

    void generate();

    bool generated;

    size_t _log2q;
    mpz_t _qDivBy2;
    mpz_t _bigmodDivBy2;
};

template <typename T, size_t Degree, size_t NbModuli, typename U>
class Params
{
public:
    static constexpr U PlaintextModulus = nfl::params<U>::P[0];
    using P = Poly<T, Degree, NbModuli>;
    using PZ = PolyZ<T, Degree, NbModuli>;

    static Params p;

    inline const mpz_t& plaintextModulus() {generate(); return _plaintextModulus;}
    inline const P& delta() {generate(); return _delta;}
    inline const P& delta_shoup() {generate(); return _delta_shoup;}

    inline size_t noise_max() {generate(); return _noise_max;}

private:
    Params();
    ~Params();

    void generate();

    bool generated;

    mpz_t _plaintextModulus;
    P _delta;
    P _delta_shoup;
    size_t _noise_max;
};


template <typename T, size_t Degree, size_t NbModuli>
ParamsCT<T, Degree, NbModuli> ParamsCT<T, Degree, NbModuli>::p;

template <typename T, size_t Degree, size_t NbModuli>
ParamsCT<T, Degree, NbModuli>::ParamsCT() :
    generated(false)
{
}

template <typename T, size_t Degree, size_t NbModuli>
void ParamsCT<T, Degree, NbModuli>::generate()
{
    if (!generated)
    {
        _log2q = mpz_sizeinbase(P::moduli_product(), 2);
        // log_2(q)+1
        mpz_fdiv_q_ui(_qDivBy2, P::moduli_product(), 2);
        mpz_fdiv_q_ui(_bigmodDivBy2, PZ::moduli_product(), 2);

        // Set generated flag
        generated = true;
    }
}


template <typename T, size_t Degree, size_t NbModuli, typename U>
Params<T, Degree, NbModuli, U> Params<T, Degree, NbModuli, U>::p;

template <typename T, size_t Degree, size_t NbModuli, typename U>
Params<T, Degree, NbModuli, U>::Params() :
    generated(false)
{
}

template <typename T, size_t Degree, size_t NbModuli, typename U>
void Params<T, Degree, NbModuli, U>::generate()
{
    if (!generated)
    {
        // Misc parameters
        mpz_init(_plaintextModulus);

        mpz_set_ui(_plaintextModulus, PlaintextModulus);

        // Define delta the polynomial of constant coeff = floor(modulus / plaintext
        // modulus)
        mpz_class d;
        mpz_fdiv_q(d.get_mpz_t(), P::moduli_product(),
                   _plaintextModulus);
        _delta = d;
        _delta.ntt_pow_phi();
        _delta_shoup = nfl::compute_shoup(_delta);

        // Max noise
        _noise_max =
            mpz_sizeinbase(P::moduli_product(), 2) - 1 -
            mpz_sizeinbase(_plaintextModulus, 2);

        // Set generated flag
        generated = true;
    }
}

template <typename T, size_t Degree, size_t NbModuli, typename U>
Params<T, Degree, NbModuli, U>::~Params()
{
    if (generated)
        mpz_clear(_plaintextModulus);
}


/** The following functions are taken from FV-NFLlib licensed under GPLv3 **/
/** See: https://github.com/CryptoExperts/FV-NFLlib/                      **/

namespace util
{

void center(mpz_t &rop, mpz_t const &op1, mpz_t const &op2,
            mpz_t const &op2Div2);

void div_and_round(mpz_t &rop, mpz_t const &op1, mpz_t const &op2,
                   mpz_t const &op2Div2);

/**
 * center the coefficients, multiply them by "multiplier" and then divide by the
 * divisor
 * @param coefficients pointer to the initialized coefficients
 * @param degree       number of coefficients to compute
 * @param multiplier   multiplier for the internal multiplication
 * @param divisor      denominator
 * @param divisorDiv2  floor(denominator/2)
 * @param mod_init     modulus of the initial coefficients
 * @param mod_initDiv2 floor(modulus/2)
 */
template <size_t Degree>
void reduce(std::array<mpz_t, Degree> &coefficients, mpz_t const &multiplier,
            mpz_t const &divisor, mpz_t const &divisorDiv2,
            mpz_t const &mod_init, mpz_t const &mod_initDiv2)
{
    for (unsigned i = 0; i < Degree; i++) {
        // Center with mod_init
        center(coefficients[i], coefficients[i], mod_init, mod_initDiv2);
        // Multiply by multiplier
        mpz_mul(coefficients[i], coefficients[i], multiplier);
        // Divide by divisor
        div_and_round(coefficients[i], coefficients[i], divisor, divisorDiv2);
        // reduction will be done during the mpz2poly()'s calls
        // otherwise one needs to do it
    }
}

/**
 * Lift the polynomial into an array of integer coefficients
 * @param coefficients pointer to the array of coefficients
 * @param c            polynomial P
 */
template <typename T, size_t Degree, size_t NbModuli>
void lift(std::array<mpz_t, Degree> &coefficients,
          PolyZ<T, Degree, NbModuli> const &c)
{
    using PZ = PolyZ<T, Degree, NbModuli>;

    // Compute the inverse NTT
    PZ other{c};
    other.invntt_pow_invphi();

    // transform the poly into coefficients
    other.poly2mpz(coefficients);
}

/**
 * Convert a polynomial P into a polynomial PZ
 * @param new_c    target polynomial
 * @param c        initial polynomial
 * @param ntt_form boolean to keep the NTT form if any
 */
template <typename T, size_t Degree, size_t NbModuli>
void convert(PolyZ<T, Degree, NbModuli> &new_c,
             Poly<T, Degree, NbModuli> const &c,
             bool ntt_form = true)
{
    using P = Poly<T, Degree, NbModuli>;
    using PZ = PolyZ<T, Degree, NbModuli>;

    size_t size_for_shoup = P::bits_in_moduli_product() +
                            sizeof(typename P::value_type) * CHAR_BIT +
                            nfl::static_log2<P::nmoduli>::value + 1;

    // Copy c
    P other{c};

    // Compute the inverse NTT if needed
    if (ntt_form)
        other.invntt_pow_invphi();

    // Initialize temporary values
    mpz_t tmp, coefficient;
    mpz_init2(tmp, nfl::static_log2<P::nmoduli>::value + size_for_shoup);
    mpz_init2(coefficient,
              P::bits_in_moduli_product() + nfl::static_log2<P::nmoduli>::value);

    // Loop on all the coefficients of c
    for (size_t i = 0; i < P::degree; i++) {
        // Construct the i-th coefficient over ZZ
        mpz_set_ui(coefficient, 0);
        for (size_t cm = 0; cm < P::nmoduli; cm++)
            // coefficient += other(cm, i) * lifting_integers[cm]
            mpz_addmul_ui(coefficient, P::lifting_integers()[cm], other(cm, i));

        // Modular reduction modulo "moduli_product" using Shoup
        mpz_mul(tmp, coefficient, P::modulus_shoup());
        mpz_tdiv_q_2exp(tmp, tmp, size_for_shoup);  // right shift
        mpz_submul(coefficient, tmp,
                   P::moduli_product());  // coefficient -= tmp * moduli_product

        if (mpz_cmp(coefficient, P::moduli_product()) >= 0)
            mpz_sub(coefficient, coefficient, P::moduli_product());

        // Store the coefficients in new_c
        for (size_t cm = 0; cm < P::nmoduli; cm++)
             // don't need to recompute for the first moduli
            new_c(cm, i) = other(cm, i);
        for (size_t cm = P::nmoduli; cm < PZ::nmoduli; cm++)
            new_c(cm, i) = mpz_fdiv_ui(coefficient, P::get_modulus(cm));
    }

    if (ntt_form)
        new_c.ntt_pow_phi();

    // Clean
    mpz_clears(tmp, coefficient, nullptr);
}

}  // namespace util

}

#endif

