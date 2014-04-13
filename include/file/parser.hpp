#ifndef _PARSER_H_
#define _PARSER_H_

#include <vector>
#include <cstdint>
#include "boost/trie/trie_map.hpp"

namespace file
{
    std::vector<uint8_t> readBytes(const std::string& filename);

    std::vector<std::vector<uint8_t>> parse(const std::string& filename);

}

#endif /* _PARSER_H_ */
