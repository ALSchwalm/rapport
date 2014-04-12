
#include "assembly/instructions.hpp"
#include <boost/program_options.hpp>
#include <iostream>
#include <fstream>
#include <algorithm>

namespace options = boost::program_options;

std::vector<uint8_t> readBytes(std::string filename)
{
    using namespace std;

    ifstream ifs(filename, ios::binary | ios::ate);
    auto pos = ifs.tellg();

    vector<uint8_t> result(pos);

    ifs.seekg(0, ios::beg);
    auto start = &result[0];
    ifs.read(reinterpret_cast<char*>(start), pos);

    return result;
}

int main(int argc, char *argv[]) {
    options::options_description desc("Allowed options");
    desc.add_options()
        ("help", "produce help message")
        ("pad,p", options::value<int>()->default_value(0), "pad output to fill buffer")
        ("file", options::value<std::string>()->required(), "input file")
        ;

    options::variables_map vm;

    options::positional_options_description positionalOptions;
    positionalOptions.add("file", 1);

    options::store(options::command_line_parser(argc, argv).options(desc)
                   .positional(positionalOptions).run(),
                   vm);

    // Help check before notify to prevent exception if requesting help with no file
    if (vm.count("help")) {
        std::cout << desc << "\n";
        return 0;
    }

    options::notify(vm);

    auto contents = readBytes(vm["file"].as<std::string>());

    for (auto i = contents.begin(); i != contents.end(); ++i) {
        i = std::find(i, contents.end(), 0xC3);
        if (i == contents.end()) {break;}
        std::cout << std::hex << "0x"
                  << std::distance(contents.begin(), i) << std::endl;
    }
}
