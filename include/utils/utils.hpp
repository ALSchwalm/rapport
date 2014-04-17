#include <algorithm>
#include <iostream>
#include <vector>
#include "assembly/instructions.hpp"

namespace utils
{
    void writeOp(const assembly::Op_t& op, bool endl=true) {
        for (int i : op) {
            std::cout << std::hex << "0x" << i << " ";
        }
        if (endl)
            std::cout << std::endl;
    }

    //Based on http://stackoverflow.com/a/9430993/3186747
    /*
     * Returns a nested vector of each combination.
     * Example: in combinations(5, 3):
     * 3 4 means groups of
     * {{0, 1, 2}, {3}, {4, 5}},
     *
     * 2 4 means groups of
     * {{0, 1}, {2, 3}, {4, 5}}
     */
    std::vector<std::vector<int>> combinations(int max, int groups) {
        int r = groups-1;
        std::vector<char> v(max);
        std::vector<std::vector<int>> combinations;

        for (int i = 0; i < max; ++i) {
            v[i] = (i >= (max - r));
        }

        do {
            std::vector<int> innerCombinations;
            for (int i = 0; i < max; ++i) {
                if (v[i]) {
                    innerCombinations.push_back(i+1);
                }
            }
            combinations.emplace_back(std::move(innerCombinations));
        } while (std::next_permutation(v.begin(), v.end()));

        return combinations;
    }

    std::vector<assembly::Op_t> codesFromCombination(const std::vector<int>& combination,
                                                     std::vector<uint8_t>::iterator retn,
                                                     int depth) {
        using namespace assembly;

        std::vector<Op_t> chain;
        for (unsigned int i = 0; i < combination.size(); ++i) {
            if (i == 0 ) {
                chain.emplace_back(retn - combination[i], retn);
            }
            if (i == combination.size()-1) {
                chain.emplace_back(retn - depth, retn - combination[i]);
            }
            if (i > 0 && i < combination.size()-1){
                chain.emplace_back(retn - combination[i],
                                   retn - combination[i-1]);
            }
        }
        std::reverse(chain.begin(), chain.end());/*
        std::cout << "Chain:\n";
        for (unsigned int i = 0; i < chain.size() ; ++i) {
            std::cout << i+1 << " ";
            writeOp(chain[i]);
        }
                                                 */
        return chain;
    }
}
