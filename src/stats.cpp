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

#include "stats.hpp"

#include <cmath>
#include <algorithm>

namespace oride {

double Stats::mean() const
{
    double result = 0;
    for (double x : mValues)
        result += x;
    return result / mValues.size();
}

double Stats::mean2() const
{
    double result = 0;
    for (double x : mValues)
        result += x*x;
    return result / mValues.size();
}

double Stats::stddev() const
{
    double m = mean();
    return std::sqrt(mean2() - m*m);
}

double Stats::median() const
{
    int l = mValues.size();
    if (l == 0)
        return 0;

    auto copy = mValues;
    std::sort(copy.begin(), copy.end());
    if (l % 2 == 1)
        return copy[l/2];
    else
        return (copy[(l-1)/2] + copy[l/2]) / 2.0;
}

std::ostream& operator<<(std::ostream& out, const Stats& stats)
{
    return out << "{" << stats.mean() << " +- " << stats.stddev() << " : " << stats.median() << " / " << stats.count() << "}";
}

}

