#ifndef _DISASSEMBLE_H_
#define _DISASSEMBLE_H_

#include <vector>
#include <string>
#include <tuple>
#include <capstone/capstone.h>

namespace assembly {
    using Op_t = std::vector<uint8_t>;
    using Ins_t = std::pair<Op_t, std::string>;

    // Determine if opcode is valid in a given architecture
    bool isValidOpcode(const Op_t& opcode,
                       cs_arch arch = CS_ARCH_X86,
                       cs_mode mode = CS_MODE_64);

    // Disassemble bytes as opcodes of a given architecture
    std::vector<Ins_t> disassemble(const std::vector<uint8_t>& data,
                                   cs_arch arch = CS_ARCH_X86,
                                   cs_mode mode = CS_MODE_64);

    // Convert strings to architecture/mode enums and get their address size (in bytes)
    std::tuple<cs_arch, cs_mode, short> toArchMode(const std::string& arch,
                                                   const std::string& mode);

    // Get a vector of opcodes which terminate gadets on an architecture
    std::vector<uint8_t> getTerminators(cs_arch);
}



#endif /* _DISASSEMBLE_H_ */
