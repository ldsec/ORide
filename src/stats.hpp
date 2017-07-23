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

#ifndef ORIDE__STATS_HPP
#define ORIDE__STATS_HPP

#include <vector>
#include <iostream>

namespace oride {

// Compute simple statistics: mean, variance, median
class Stats
{
public:
    Stats() = default;

    inline void add(double v)
        {mValues.push_back(v);}

    inline int count() const
        {return mValues.size();}
    double mean() const;
    double stddev() const;
    double median() const;

private:
    double mean2() const;

    std::vector<double> mValues;
};

std::ostream& operator<<(std::ostream& out, const Stats& stats);

}

#endif

