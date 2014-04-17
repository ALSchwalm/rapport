
#include "file/parser.hpp"
#include <boost/algorithm/string/predicate.hpp>
#include <boost/filesystem.hpp>
#include <fstream>
#include <sstream>
#include <vector>
#include <stdexcept>

namespace file
{
    namespace fs = boost::filesystem;

    namespace {
        uint8_t toByte(const std::string& hexByte) {
            std::stringstream ss;;
            uint16_t value;
            ss << std::hex << hexByte;
            ss >> value;
            return value;
        }
    }

    std::vector<uint8_t> readBytes(const std::string& filename)
    {
        if (!fs::exists(filename)) {
            throw std::invalid_argument("No such file: " + filename);
        }

        using namespace std;
        ifstream ifs(filename, ios::binary | ios::ate);
        auto pos = ifs.tellg();

        vector<uint8_t> result(pos);

        ifs.seekg(0, ios::beg);
        auto start = &result[0];
        ifs.read(reinterpret_cast<char*>(start), pos);

        return result;
    }

    std::vector<std::vector<uint8_t>> parse(const std::string& filename)
    {
        if (!fs::exists(filename)) {
            throw std::invalid_argument("No such file: " + filename);
        }

        std::vector<std::vector<uint8_t>> output;
        std::ifstream ifs(filename);
        std::stringstream ss;
        std::string token, line;

        while (std::getline(ifs, line)) {
            ss << line;
            std::vector<uint8_t> opcode;
            while( ss >> token ) {
                if (boost::algorithm::starts_with(token, "//")) {
                    break;
                }
                opcode.push_back(toByte(token));
            }
            ss.str("");
            output.push_back(opcode);
        }
        return output;
    }
}
