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

#ifndef ORIDE__FV_HPP
#define ORIDE__FV_HPP

#include "util.hpp"

namespace oride {

// Classes that implement the FV scheme
// Key pair
template <typename T, size_t Degree, size_t NbModuli>
class SecretKey;
template <typename T, size_t Degree, size_t NbModuli>
class AbstractPublicKey;
// Plaintext
template <typename U, size_t Degree>
class Plaintext;
// Ciphertext of degree 2
template <typename T, size_t Degree, size_t NbModuli, typename U>
class Ciphertext2;
// Ciphertext of degree 3 (not relinearized)
template <typename T, size_t Degree, size_t NbModuli, typename U>
class Ciphertext3;

// Classes to serialize keys/ciphertexts
template <typename T, size_t Degree, size_t NbModuli>
class SerializeKeys;
template <typename T, size_t Degree, size_t NbModuli, typename U>
class SerializeCT;


template <typename T, size_t Degree, size_t NbModuli>
class SecretKey
{
    friend class AbstractPublicKey<T, Degree, NbModuli>;
    friend class SerializeKeys<T, Degree, NbModuli>;

    using P = Poly<T, Degree, NbModuli>;

    P value;
    P value_shoup;

public:
    // Generate secret key from Gaussian distribution
    SecretKey() :
        value(typename Gauss<T>::Struct(&Gauss<T>::fg_prng_sk))
    {
        value.ntt_pow_phi();  // store in NTT form
        value_shoup = nfl::compute_shoup(value);
    }


    template <typename U>
    Plaintext<U, Degree> decrypt(const Ciphertext2<T, Degree, NbModuli, U>& ct) const
    {
        P numerator{ct.c0 + ct.c1 * value};
        return decrypt<U>(numerator);
    }

    template <typename U>
    Plaintext<U, Degree> decrypt(const Ciphertext3<T, Degree, NbModuli, U>& ct) const
    {
        P numerator{ct.c0 + ct.c1 * value + ct.c2 * value * value};
        return decrypt<U>(numerator);
    }

private:
    SecretKey(P&& _value) :
        value(std::move(_value)),
        value_shoup(nfl::compute_shoup(value))
    {
    }

    // Helper function to decrypt ciphertext
    template <typename U>
    Plaintext<U, Degree> decrypt(P& numerator) const
    {
        using PrmsCT = ParamsCT<T, Degree, NbModuli>;
        using Prms = Params<T, Degree, NbModuli, U>;
        using PT = Plaintext<U, Degree>;

        std::array<mpz_t, Degree> p;
        for (size_t i = 0; i < Degree; i++)
            mpz_init(p[i]);

        // Get the polynomial
        numerator.invntt_pow_invphi();
        numerator.poly2mpz(p);

        // Reduce the coefficients
        util::reduce(
            p, Prms::p.plaintextModulus(),
            P::moduli_product(), PrmsCT::p.qDivBy2(), P::moduli_product(),
            PrmsCT::p.qDivBy2());

        PT pt = PT::zero();
        for (size_t i = 0; i < Degree; i++)
        {
            mpz_mod(p[i], p[i], Prms::p.plaintextModulus());
            pt.set(i, mpz_get_ui(p[i]));
            mpz_clear(p[i]);
        }

        return pt;
    }
};


// Lightweight public key class that does not contain shoup polynomials.
// This is useful for a peer that does not encrypt data.
template <typename T, size_t Degree, size_t NbModuli>
class AbstractPublicKey
{
    friend class SerializeKeys<T, Degree, NbModuli>;

    using P = Poly<T, Degree, NbModuli>;
    using SK = SecretKey<T, Degree, NbModuli>;

protected:
    P a, b;

public:
    AbstractPublicKey(const SK& sk)
    {
        // random a (already in NTT form)
        a = nfl::uniform();

        // b = small - a*sk
        b = typename Gauss<T>::Struct(&Gauss<T>::fg_prng_pk);
        b.ntt_pow_phi();  // transform via NTT
        b = b - a * sk.value;
    }

private:
    AbstractPublicKey(P&& _a, P&& _b) :
        a(std::move(_a)),
        b(std::move(_b))
    {
    }
};

// A fully-fledged public key.
template <typename T, size_t Degree, size_t NbModuli>
class PublicKey : public AbstractPublicKey<T, Degree, NbModuli>
{
    using P = Poly<T, Degree, NbModuli>;

    P a_shoup, b_shoup;

public:
    PublicKey(AbstractPublicKey<T, Degree, NbModuli>&& pk) :
        AbstractPublicKey<T, Degree, NbModuli>(std::move(pk)),
        a_shoup(nfl::compute_shoup(this->a)),
        b_shoup(nfl::compute_shoup(this->b))
    {
    }

    template <typename U>
    Ciphertext2<T, Degree, NbModuli, U> encrypt(const Plaintext<U, Degree>& pt) const
    {
        using Prms = Params<T, Degree, NbModuli, U>;
        using CT2 = Ciphertext2<T, Degree, NbModuli, U>;

        P m = CT2::to_cipher_poly(pt);

        // Generate a small u
        P u{typename Gauss<T>::Struct(&Gauss<T>::fg_prng_enc)};
        u.ntt_pow_phi();

        // Generate ct = (c0, c1)
        CT2 ct;

        // where c0 = b*u + Delta*m + small error
        ct.c0 = typename Gauss<T>::Struct(&Gauss<T>::fg_prng_enc);
        ct.c0.ntt_pow_phi();
        ct.c0 = ct.c0 + nfl::shoup(u * this->b, b_shoup) +
                nfl::shoup(m * Prms::p.delta(), Prms::p.delta_shoup());

        // where c1 = a*u + small error
        ct.c1 = typename Gauss<T>::Struct(&Gauss<T>::fg_prng_enc);
        ct.c1.ntt_pow_phi();
        ct.c1 = ct.c1 + nfl::shoup(u * this->a, a_shoup);

        return ct;
    }
};


template <typename U, size_t Degree>
class Plaintext
{
    using P = nfl::poly<U, Degree, 1>;

    P p;

public:
    static Plaintext zero()
    {
        return Plaintext();
    }

    Plaintext(const std::array<U, Degree>& m)
    {
        for (size_t i = 0; i < Degree; i++)
            p.data()[i] = m[i];
    }

    U get(unsigned int i) const
    {
        return p.cdata()[i];
    }

    void set(unsigned int i, U x)
    {
        p.data()[i] = x;
    }

    // In-place (inv-)NTT
    void ntt()
    {
        p.ntt_pow_phi();
    }

    void invntt()
    {
        p.invntt_pow_invphi();
    }

private:
    Plaintext() = default;
};

template <typename T, size_t Degree, size_t NbModuli, typename U>
class Ciphertext2
{
    friend class SecretKey<T, Degree, NbModuli>;
    friend class PublicKey<T, Degree, NbModuli>;
    friend class SerializeCT<T, Degree, NbModuli, U>;

    using Prms = Params<T, Degree, NbModuli, U>;
    using P = Poly<T, Degree, NbModuli>;
    using PT = Plaintext<U, Degree>;
    using CT3 = Ciphertext3<T, Degree, NbModuli, U>;

    P c0, c1;

public:
    static Ciphertext2 zero()
    {
        return Ciphertext2();
    }

    // Transform a public plaintext into the ciphertext space.
    // This does not require a public key and does not increase noise.
    // This is useful to mask encrypted ciphertexts by multiplying them by a
    // constant, public polynomial.
    static Ciphertext2 constant(const PT& pt)
    {
        P m = to_cipher_poly(pt);

        // Generate ct = (Delta*m, 0)
        Ciphertext2 ct;
        ct.c0 = nfl::shoup(m * Prms::p.delta(), Prms::p.delta_shoup());

        return ct;
    }

    static P to_cipher_poly(const PT& pt)
    {
        std::array<mpz_t, Degree> p;
        for (size_t i = 0; i < Degree; i++)
        {
            mpz_init(p[i]);
            mpz_set_ui(p[i], pt.get(i));
        }

        P result;
        result.mpz2poly(p);
        result.ntt_pow_phi();

        for (size_t i = 0; i < Degree; i++)
            mpz_clear(p[i]);

        return result;
    }


    Ciphertext2& operator+=(const P& p)
    {
        c0 = c0 + nfl::shoup(p * Prms::p.delta(), Prms::p.delta_shoup());
        return *this;
    }

    Ciphertext2& operator-=(const P& p)
    {
        c0 = c0 - nfl::shoup(p * Prms::p.delta(), Prms::p.delta_shoup());
        return *this;
    }

    Ciphertext2& operator*=(const P& p)
    {
        c0 = c0 * p;
        c1 = c1 * p;
        return *this;
    }


    inline Ciphertext2& operator+=(const PT& pt)
    {
        return *this += to_cipher_poly(pt);
    }

    inline Ciphertext2& operator-=(const PT& pt)
    {
        return *this -= to_cipher_poly(pt);
    }

    inline Ciphertext2& operator*=(const PT& pt)
    {
        return *this *= to_cipher_poly(pt);
    }


    Ciphertext2& operator+=(const Ciphertext2& ct)
    {
        c0 = c0 + ct.c0;
        c1 = c1 + ct.c1;
        return *this;
    }

    Ciphertext2& operator-=(const Ciphertext2& ct)
    {
        c0 = c0 - ct.c0;
        c1 = c1 - ct.c1;
        return *this;
    }

    // Multiply degree-2 ciphertexts without relinearization.
    CT3 mul_norelin(const Ciphertext2& ct) const
    {
        using PrmsCT = ParamsCT<T, Degree, NbModuli>;
        using PZ = PolyZ<T, Degree, NbModuli>;

        size_t bits_in_moduli_product = P::bits_in_moduli_product();

        // Allocations
        PZ c00, c10, c01, c11, c1b;

        // View the polynomials as PZ polynomials
        util::convert(c00, c0);
        util::convert(c01, c1);
        util::convert(c10, ct.c0);
        util::convert(c11, ct.c1);

        // Compute products "over ZZ"
        c1b = c00 * c11 + c01 * c10;
        c00 = c00 * c10;
        c11 = c01 * c11;

        // Multiply by t/q
        P r0, r1, r2;
        std::array<mpz_t, Degree> coefficients;
        for (size_t i = 0; i < Degree; i++)
            mpz_init2(coefficients[i], (bits_in_moduli_product << 2));

        util::lift<T, Degree, NbModuli>(coefficients, c00);
        util::reduce(
            coefficients, Prms::p.plaintextModulus(),
            P::moduli_product(), PrmsCT::p.qDivBy2(), PZ::moduli_product(),
            PrmsCT::p.bigmodDivBy2());
        r0.mpz2poly(coefficients);
        r0.ntt_pow_phi();

        util::lift<T, Degree, NbModuli>(coefficients, c1b);
        util::reduce(
            coefficients, Prms::p.plaintextModulus(),
            P::moduli_product(), PrmsCT::p.qDivBy2(), PZ::moduli_product(),
            PrmsCT::p.bigmodDivBy2());
        r1.mpz2poly(coefficients);
        r1.ntt_pow_phi();

        util::lift<T, Degree, NbModuli>(coefficients, c11);
        util::reduce(
            coefficients, Prms::p.plaintextModulus(),
            P::moduli_product(), PrmsCT::p.qDivBy2(), PZ::moduli_product(),
            PrmsCT::p.bigmodDivBy2());
        r2.mpz2poly(coefficients);
        r2.ntt_pow_phi();

        // Clean
        for (size_t i = 0; i < Degree; i++)
            mpz_clear(coefficients[i]);

        return CT3(std::move(r0), std::move(r1), std::move(r2));
    }

private:
    Ciphertext2() = default;

    Ciphertext2(P&& _c0, P&& _c1) :
        c0(std::move(_c0)),
        c1(std::move(_c1))
    {
    }
};

template <typename T, size_t Degree, size_t NbModuli, typename U>
class Ciphertext3
{
    friend class SecretKey<T, Degree, NbModuli>;
    friend class PublicKey<T, Degree, NbModuli>;
    friend class SerializeCT<T, Degree, NbModuli, U>;
    friend class Ciphertext2<T, Degree, NbModuli, U>;

    using Prms = Params<T, Degree, NbModuli, U>;
    using P = Poly<T, Degree, NbModuli>;
    using PT = Plaintext<U, Degree>;

    P c0, c1, c2;

public:
    Ciphertext3& operator+=(const Ciphertext3& ct)
    {
        c0 = c0 + ct.c0;
        c1 = c1 + ct.c1;
        c2 = c2 + ct.c2;
        return *this;
    }

private:
    Ciphertext3() = default;

    Ciphertext3(P&& _c0, P&& _c1, P&& _c2) :
        c0(std::move(_c0)),
        c1(std::move(_c1)),
        c2(std::move(_c2))
    {
    }
};

}

#endif

