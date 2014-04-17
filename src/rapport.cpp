
#include "assembly/instructions.hpp"
#include "file/parser.hpp"
#include "utils/utils.hpp"
#include "boost/trie/trie_map.hpp"
#include <boost/program_options.hpp>
#include <iostream>
#include <algorithm>

namespace options = boost::program_options;
using namespace assembly;

int main(int argc, char *argv[]) {
    try {
        options::options_description desc("Allowed options");
        desc.add_options()
            ("help", "produce help message")
            ("base,b", options::value<std::string>()->default_value("0x0"), "base address")
            ("pad,p", options::value<uint32_t>()->default_value(0), "pad output to fill buffer")
            ("target", options::value<std::string>()->required(), "file to search for ROP chains")
            ("input", options::value<std::string>()->required(), "instructions to locate")
            ("depth", options::value<int>()->default_value(6), "bytes to search before RETN")
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

        //Base is actually a hex number
        std::stringstream ss;
        uint32_t base;
        ss << std::hex << vm["base"].as<std::string>();
        ss >> base;

        auto contents = file::readBytes(vm["target"].as<std::string>());
        auto input = file::parse(vm["input"].as<std::string>());

        boost::tries::trie_map<Op_t, uint32_t> trie;

        //Locate all RETNs
        std::vector<Op_t::iterator> retns;
        for (auto i = contents.begin(); i != contents.end(); ++i) {
            if (*i == assembly::RETN) {
                retns.push_back(i);
            }
        }

        //Find the opcodes executable from the RETNs
        auto depth = vm["depth"].as<int>();
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
            for (auto address : addresses) {
                std::cout << std::hex << "0x" << base + address << std::endl;
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
