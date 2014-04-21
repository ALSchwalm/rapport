#include "assembly/disassemble.hpp"
#include <stdexcept>

namespace assembly {

    bool isValidOpcode(const Op_t& opcode, cs_arch arch, cs_mode mode) {
        csh handle;
        cs_insn *insn;
        size_t count;

        if (cs_open(arch, mode, &handle) != CS_ERR_OK)
            return false;

        count = cs_disasm_ex(handle, opcode.data(), opcode.size(), 0, 0, &insn);
        if (count > 0) {
            cs_close(&handle);
            cs_free(insn, count);
            return true;
        }
        cs_close(&handle);
        return false;
    }

    std::vector<Ins_t> disassemble(const std::vector<uint8_t>& data,
                                   cs_arch arch,
                                   cs_mode mode) {
        csh handle;
        cs_insn *insn;
        std::vector<Ins_t> instructions;
        size_t count;

        if (cs_open(arch, mode, &handle) != CS_ERR_OK)
            throw std::invalid_argument("Unable to open capstone handle");
        count = cs_disasm_ex(handle, data.data(), data.size(), 0, 0, &insn);
        if (count > 0) {
            for (size_t i = 0; i < count; ++i) {
                Op_t opcode(insn[i].bytes, insn[i].bytes+insn[i].size);
                std::string str = std::string(insn[i].mnemonic) + " " + std::string(insn[i].op_str);
                Ins_t instruction(std::move(opcode), std::move(str));
                instructions.emplace_back(std::move(instruction));
            }
            cs_free(insn, count);
        }
        cs_close(&handle);
        return instructions;
    }
}
