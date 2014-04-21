#ifndef _DISASSEMBLE_H_
#define _DISASSEMBLE_H_

#include <vector>
#include <string>
#include <capstone/capstone.h>

namespace assembly {
    using Op_t = std::vector<uint8_t>;
    using Ins_t = std::pair<Op_t, std::string>;

    bool isValidOpcode(const Op_t& opcode,
                       cs_arch arch = CS_ARCH_X86,
                       cs_mode mode = CS_MODE_64);

    std::vector<Ins_t> disassemble(const std::vector<uint8_t>& data,
                                   cs_arch arch = CS_ARCH_X86,
                                   cs_mode mode = CS_MODE_64);
}



#endif /* _DISASSEMBLE_H_ */
