
#include "file/parser.hpp"
#include "utils/utils.hpp"
#include "boost/trie/trie_map.hpp"
#include <boost/program_options.hpp>
#include <iostream>
#include <algorithm>

namespace options = boost::program_options;
using Op_t = std::vector<uint8_t>;

int main(int argc, char *argv[]) {
    try {
        int depth;
        options::options_description desc("Allowed options");
        desc.add_options()
            ("help", "produce help message")
            ("base,b", options::value<std::string>()->default_value("0x0"), "base address")
            ("pad,p", options::value<uint32_t>()->default_value(0), "pad output to fill buffer")
            ("target", options::value<std::string>()->required(), "file from which to build ROP chain")
            ("input", options::value<std::string>()->required(), "instructions to be executed")
            ("depth", options::value<int>(&depth)->default_value(6), "bytes to search before RETN")
            ("retn", options::value<std::string>()->default_value("0xC3"), "opcode for REN")
            ("pprint", "print easily readable (but not usable) results")
            ;

        options::variables_map vm;

        options::positional_options_description positionalOptions;
        positionalOptions.add("target", 1);
        positionalOptions.add("input", 1);

        options::store(options::command_line_parser(argc, argv).options(desc)
                       .positional(positionalOptions).run(),
                       vm);

        // Help check before notify to prevent exception if requesting help with no file
        if (vm.count("help")) {
            std::cout << desc << std::endl;
            return 0;
        }

        options::notify(vm);

        //Convert hex string arguments to integers
        std::stringstream ss;
        uint32_t base;
        uint32_t retn;
        ss << std::hex << vm["base"].as<std::string>();
        ss >> base;
        ss.clear();
        ss << std::hex << vm["retn"].as<std::string>();
        ss >> retn;

        auto contents = file::readBytes(vm["target"].as<std::string>());
        auto input = file::parse(vm["input"].as<std::string>());

        boost::tries::trie_map<Op_t, uint32_t> trie;

        //Locate all RETNs
        std::vector<Op_t::iterator> retns;
        for (auto i = contents.begin(); i != contents.end(); ++i) {
            if (*i == retn) {
                retns.push_back(i);
            }
        }

        //Find the opcodes executable from the RETNs
        for (auto retn : retns) {
            for (int innerDepth = 1; innerDepth < depth; ++innerDepth) {

                if (retn - innerDepth < contents.begin()) {
                    break;
                }

                for (auto groups = 1; groups <= innerDepth; ++groups) {
                    for (const auto& combination : utils::combinations(innerDepth, groups)) {
                        auto chain = utils::codesFromCombination(combination, retn, innerDepth);
                        trie[chain] = std::distance(contents.begin(), retn-innerDepth);
                    }
                }
            }
        }

        //Determine where to jump to execute the instructions in the input
        std::vector<uint32_t> addresses;
        bool solutionExists = false;
        for (auto i = input.begin(), j = input.begin(); j != input.end()+1; ++j) {

            std::vector<Op_t> chain(i, j);
            if (trie[chain] != 0) {
                addresses.push_back(trie[chain]);
                i = j;
                if (j == input.end()) {
                    solutionExists = true;
                }
            }
        }

        //Print the solution
        if (solutionExists) {
            std::cout << std::string(vm["pad"].as<uint32_t>(), '~');
            for (auto address : addresses) {
                auto addr = base + address;

                if (vm.count("pprint")) {
                    std::cout << std::hex << addr << std::endl;
                }
                else {
                    for(uint8_t i = 0; i < 4; ++i) {
                        auto shiftAddr = addr;
                        char c = shiftAddr >> (i*8);
                        std::cout << c;
                    }
                }
            }
        }
        else {
            std::cout << "Unable to find a solution\n";
        }
    }
    catch (const std::exception& e) {
        std::cout << e.what() << std::endl;
    }
}
