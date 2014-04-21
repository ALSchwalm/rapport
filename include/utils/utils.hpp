#include <iostream>
#include <vector>

namespace utils
{
    inline void writeOp(const std::vector<uint8_t>& op, bool endl=true) {
        for (int i : op) {
            std::cout << std::hex << "0x" << i << " ";
        }
        if (endl)
            std::cout << std::endl;
    }
}
