# ORide: A Privacy-Preserving yet Accountable Ride-Hailing Service
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/gpl-3.0.txt


# This is a Sage script to generate NTT parameters for NFLlib.

# Generate moduli of the form p = 2**a - i*2**b + 1
def generate(max_degree, modulus_bits, representation_bits, postfix, count=-1):
    b = max_degree + 1
    n = 2**b
    a = modulus_bits
    nimble = 2**representation_bits

    num_found = 0
    i = 0
    results = []
    while True:
        i += 1
        p = 2**a - i * 2**b + 1
        if p <= 1:
            break

        if not is_prime(p):
            continue
        if (p - 1) % n != 0:
            continue

        g = primitive_root(p)
        r = power_mod(g, int((p-1)/n), p)

        inv = power_mod(2**max_degree, p-2, p)

        q = int(nimble*nimble / p) % nimble

        #print("found p = " + str(p) + " = 2^" + str(a) + " - " + str(i) + "*2^" + str(b) + " - 1 ; inv = " + str(inv) + " ; generator g = " + str(g) + " ; primitive 2^" + str(b) + "-th root of unity r = " + str(r) + " ; quotient q = " + str(q))
        #print("p = " + str(p) + " ; inv = " + str(inv) + " ; q = " + str(q) + " ; r = " + str(r))
        results.append({'p': p, 'i': inv, 'q': q, 'r': r})

        num_found += 1
        if num_found == count:
            break

    print("// Generated with Sage")
    print("static constexpr unsigned int kMaxNbModuli = " + str(len(results)) + ";")
    print("static constexpr value_type P[kMaxNbModuli] = {" + ", ".join(str(x['p']) + postfix for x in results) + "};")
    print("static constexpr value_type Pn[kMaxNbModuli] = {" + ", ".join(str(x['q']) + postfix for x in results) + "};")
    print("static constexpr unsigned int kModulusBitsize = " + str(modulus_bits) + ";")
    print("static constexpr unsigned int kModulusRepresentationBitsize = " + str(representation_bits) + ";")
    print("static constexpr value_type primitive_roots[kMaxNbModuli] = {" + ", ".join(str(x['r']) + postfix for x in results) + "};")
    print("static constexpr value_type invkMaxPolyDegree[kMaxNbModuli] = {" + ", ".join(str(x['i']) + postfix for x in results) + "};")
    print("static constexpr unsigned int kMaxPolyDegree = " + str(2**max_degree) + ";")

def generate_all():
    #generate(9, 14, 16, 'U', 2)
    #generate(12, 21, 32, 'UL')
    generate(12, 20, 32, 'UL')
    #generate(10, 15, 32, 'UL')
    #generate(15, 30, 32, 'UL', 291)
    #generate(20, 62, 64, 'ULL', 1000)

