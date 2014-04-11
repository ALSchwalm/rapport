
#include "assembly/instructions.hpp"
#include <boost/program_options.hpp>
#include <iostream>

namespace options = boost::program_options;

int main(int argc, char *argv[]) {
    options::options_description desc("Allowed options");
    desc.add_options()
        ("help", "produce help message")
        ("pad,p", options::value<int>(), "pad output to fill buffer")
        ("file", options::value<std::string>()->required(), "input file")
        ;

    options::variables_map vm;

    options::positional_options_description positionalOptions;
    positionalOptions.add("file", 1);

    options::store(options::command_line_parser(argc, argv).options(desc)
                   .positional(positionalOptions).run(),
                   vm);

    options::notify(vm);

    if (vm.count("help")) {
        std::cout << desc << "\n";
        return 0;
    }
}
