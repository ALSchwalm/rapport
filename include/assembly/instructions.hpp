#ifndef _INSTRUCTIONS_H_
#define _INSTRUCTIONS_H_

#include <set>
#include <vector>
#include <cstdint>

namespace assembly
{
    using Op_t = std::vector<uint8_t>;

    // Storage for all of the opcodes
    extern const std::set<Op_t> opcodes;

    inline bool isValidOp(const Op_t& op) {
        return opcodes.find(op) != opcodes.end();
    }
}

#endif /* _INSTRUCTIONS_H_ */
