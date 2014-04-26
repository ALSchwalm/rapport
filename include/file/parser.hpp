#ifndef _PARSER_H_
#define _PARSER_H_

#include <vector>
#include <cstdint>
#include <string>
#include <capstone/capstone.h>

namespace file
{
    std::vector<uint8_t> readBytes(const std::string& filename);

    std::vector<std::vector<uint8_t>> parse(const std::string& filename,
                                            cs_arch arch, cs_mode mode);

}

#endif /* _PARSER_H_ */
