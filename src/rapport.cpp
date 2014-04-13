
#include "assembly/instructions.hpp"
#include "file/parser.hpp"
#include "boost/trie/trie_map.hpp"
#include <boost/program_options.hpp>
#include <iostream>
#include <algorithm>

namespace options = boost::program_options;

int main(int argc, char *argv[]) {
    try {
        options::options_description desc("Allowed options");
        desc.add_options()
            ("help", "produce help message")
            ("base,b", options::value<std::string>()->default_value("0x0"), "base address")
            ("pad,p", options::value<uint32_t>()->default_value(0), "pad output to fill buffer")
            ("target", options::value<std::string>()->required(), "file to search for ROP chains")
            ("input", options::value<std::string>()->required(), "instructions to locate")
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
            std::cout << desc << "\n";
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

        boost::tries::trie_map<uint8_t, uint32_t> trie;

        std::vector<std::vector<uint8_t>::iterator> retns;
        for(auto i = contents.begin(); i != contents.end(); ++i) {
            if (*i == assembly::RETN) {
                retns.push_back(i);
            }
        }

        for(auto retn : retns) {
            std::cout << std::hex << std::distance(contents.begin(), retn) << std::endl;
        }

    }
    catch (const std::exception& e) {
        std::cout << e.what() << std::endl;
    }
}
