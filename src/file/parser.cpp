
#include "file/parser.hpp"
#include "assembly/disassemble.hpp"
#include "boost/trie/trie_map.hpp"
#include <fstream>
#include <sstream>
#include <vector>
#include <stdexcept>

namespace file
{
    std::vector<uint8_t> readBytes(const std::string& filename)
    {
        using namespace std;
        ifstream ifs(filename, ios::binary | ios::ate);

        if (!ifs) {
            throw std::invalid_argument("No such file: " + filename);
        }

        auto pos = ifs.tellg();

        vector<uint8_t> result(pos);

        ifs.seekg(0, ios::beg);
        auto start = &result[0];
        ifs.read(reinterpret_cast<char*>(start), pos);

        return result;
    }

    std::vector<std::vector<uint8_t>> parse(const std::string& filename,
                                            cs_arch arch, cs_mode mode)
    {
        std::vector<std::vector<uint8_t>> output;
        std::vector<uint8_t> data;
        std::ifstream ifs(filename);

        if (!ifs) {
            throw std::invalid_argument("No such file: " + filename);
        }

        std::string token, line;

        while(std::getline(ifs, line)) {
            std::stringstream ss(line);

            while(ss >> token) {
                auto base = std::stoi(token, nullptr, 16);
                data.push_back(base);
            }
        }

        auto assembly = assembly::disassemble(data, arch, mode);

        for(auto& value : assembly) {
            output.emplace_back(std::move(value.opcode));
        }

        return output;
    }
}
