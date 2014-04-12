
#include "assembly/instructions.hpp"

namespace assembly
{
    const std::set<Op_t> opcodes
    {
        {0xC3}, //ret
        {0xFF, 0xE0}, //jmp eax
        {0xFF, 0xE3}, //jmp ebx
        {0xFF, 0xE1}, //jmp ecx
        {0xFF, 0xE2}, //jmp edx
        {0xFF, 0xE7}, //jmp edi
        {0xFF, 0xE6}, //jmp esi
        {0xFF, 0xE4}, //jmp esp
        {0xFF, 0xE5}, //jmp ebp
        {0xFF, 0x20}, //jmp [eax]
        {0xFF, 0x23}, //jmp [ebx]
        {0xFF, 0x21}, //jmp [ecx]
        {0xFF, 0x22}, //jmp [edx]
        {0xFF, 0x27}, //jmp [edi]
        {0xFF, 0x26}, //jmp [esi]
        {0xFF, 0x24, 0x24}, //jmp [esp]
        {0xFF, 0x65, 0x00}, //jmp [ebp]
        {0x50}, //push eax
        {0x53}, //push ebx
        {0x51}, //push ecx
        {0x52}, //push edx
        {0x57}, //push edi
        {0x56}, //push esi
        {0x54}, //push esp
        {0x55}, //push ebp
        {0xFF, 0x30}, //push [eax]
        {0xFF, 0x33}, //push [ebx]
        {0xFF, 0x31}, //push [ecx]
        {0xFF, 0x32}, //push [edx]
        {0xFF, 0x37}, //push [edi]
        {0xFF, 0x36}, //push [esi]
        {0xFF, 0x34, 0x24}, //push [esp]
        {0xFF, 0x75, 0x00}, //push [ebp]
        {0x58}, //pop eax
        {0x5B}, //pop ebx
        {0x59}, //pop ecx
        {0x5A}, //pop edx
        {0x5F}, //pop edi
        {0x5E}, //pop esi
        {0x5C}, //pop esp
        {0x5D}, //pop ebp
    };
}
