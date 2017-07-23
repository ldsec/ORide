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

#ifndef ORIDE__SERIALIZE_HPP
#define ORIDE__SERIALIZE_HPP

#include "fv.hpp"

namespace oride {

// Serialize FV keys
template <typename T, size_t Degree, size_t NbModuli>
class SerializeKeys
{
    using PrmsCT = ParamsCT<T, Degree, NbModuli>;
    using P = Poly<T, Degree, NbModuli>;
    static constexpr size_t Nbytes = PrmsCT::Nbytes;

    using SK = SecretKey<T, Degree, NbModuli>;
    using APK = AbstractPublicKey<T, Degree, NbModuli>;

public:
    static void writeSecretKey(std::array<unsigned char, Nbytes>& buf, const SK& sk)
    {
        // write in NTT form
        std::memcpy(buf.data(), reinterpret_cast<const unsigned char*>(sk.value.poly_obj().cdata()), Nbytes);
    }

    static SK readSecretKey(const std::array<unsigned char, Nbytes>& buf)
    {
        P value;
        // read in NTT form
        std::memcpy(reinterpret_cast<unsigned char*>(value.poly_obj().data()), buf.data(), Nbytes);
        return SK(std::move(value));
    }


    static void writePublicKey(std::array<unsigned char, 2*Nbytes>& buf, const APK& apk)
    {
        // write in NTT form
        std::memcpy(buf.data()         , reinterpret_cast<const unsigned char*>(apk.a.poly_obj().cdata()), Nbytes);
        std::memcpy(buf.data() + Nbytes, reinterpret_cast<const unsigned char*>(apk.b.poly_obj().cdata()), Nbytes);
    }

    static APK readPublicKey(const std::array<unsigned char, 2*Nbytes>& buf)
    {
        P a, b;
        // read in NTT form
        std::memcpy(reinterpret_cast<unsigned char*>(a.poly_obj().data()), buf.data()         , Nbytes);
        std::memcpy(reinterpret_cast<unsigned char*>(b.poly_obj().data()), buf.data() + Nbytes, Nbytes);
        return APK(std::move(a), std::move(b));
    }
};


// Serialize ciphertexts
template <typename T, size_t Degree, size_t NbModuli, typename U>
class SerializeCT
{
    using PrmsCT = ParamsCT<T, Degree, NbModuli>;
    using P = Poly<T, Degree, NbModuli>;
    static constexpr size_t Nbytes = PrmsCT::Nbytes;

    using CT2 = Ciphertext2<T, Degree, NbModuli, U>;
    using CT3 = Ciphertext3<T, Degree, NbModuli, U>;

public:
    static void writeCiphertext2(std::array<unsigned char, 2*Nbytes>& buf, const CT2& ct)
    {
        std::memcpy(buf.data()         , reinterpret_cast<const unsigned char*>(ct.c0.poly_obj().cdata()), Nbytes);
        std::memcpy(buf.data() + Nbytes, reinterpret_cast<const unsigned char*>(ct.c1.poly_obj().cdata()), Nbytes);
    }

    static CT2 readCiphertext(const std::array<unsigned char, 2*Nbytes>& buf)
    {
        P c0, c1;
        std::memcpy(reinterpret_cast<unsigned char*>(c0.poly_obj().data()), buf.data()         , Nbytes);
        std::memcpy(reinterpret_cast<unsigned char*>(c1.poly_obj().data()), buf.data() + Nbytes, Nbytes);
        return CT2(std::move(c0), std::move(c1));
    }

    static void writeCiphertext3(std::array<unsigned char, 3*Nbytes>& buf, const CT3& ct)
    {
        std::memcpy(buf.data()           , reinterpret_cast<const unsigned char*>(ct.c0.poly_obj().cdata()), Nbytes);
        std::memcpy(buf.data() +   Nbytes, reinterpret_cast<const unsigned char*>(ct.c1.poly_obj().cdata()), Nbytes);
        std::memcpy(buf.data() + 2*Nbytes, reinterpret_cast<const unsigned char*>(ct.c2.poly_obj().cdata()), Nbytes);
    }

    static CT3 readCiphertext(const std::array<unsigned char, 3*Nbytes>& buf)
    {
        P c0, c1, c2;
        std::memcpy(reinterpret_cast<unsigned char*>(c0.poly_obj().data()), buf.data()           , Nbytes);
        std::memcpy(reinterpret_cast<unsigned char*>(c1.poly_obj().data()), buf.data() +   Nbytes, Nbytes);
        std::memcpy(reinterpret_cast<unsigned char*>(c2.poly_obj().data()), buf.data() + 2*Nbytes, Nbytes);
        return CT3(std::move(c0), std::move(c1), std::move(c2));
    }
};

}

#endif

