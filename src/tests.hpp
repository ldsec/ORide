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

#ifndef ORIDE__TESTS_HPP
#define ORIDE__TESTS_HPP

#include "util.hpp"

namespace oride {

template <typename T, size_t Degree, size_t NbModuli, typename U>
void print_params()
{
    using PrmsCT = ParamsCT<T, Degree, NbModuli>;
    using Prms = Params<T, Degree, NbModuli, U>;

    std::cerr << "Security parameters:" << std::endl;
    std::cerr << "- n = " << Degree << std::endl;
    std::cerr << "- log2q = " << PrmsCT::p.log2q() << std::endl;
    std::cerr << "Constants:" << std::endl;
    std::cerr << "- plaintextModulus = " << mpz_class(Prms::p.plaintextModulus()).get_str() << std::endl;
    std::cerr << "- qDivBy2 = " << mpz_class(PrmsCT::p.qDivBy2()).get_str() << std::endl;
    std::cerr << "- bigmodDivBy2 = " << mpz_class(PrmsCT::p.bigmodDivBy2()).get_str() << std::endl;

    std::cerr << "Sizes of messages:" << std::endl;
    std::cerr << "- public key = " << PrmsCT::bytesPublicKey << " bytes" << std::endl;
    std::cerr << "- ciphertext2 = " << PrmsCT::bytesCiphertext2 << " bytes" << std::endl;
    std::cerr << "- ciphertext3 = " << PrmsCT::bytesCiphertext3 << " bytes" << std::endl;
}

}

#endif

