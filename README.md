Rapport
=======

A utility to aid in the location and usage of ROP 'gadgets'.

Features
========

Rapport will locate and display 'gadgets' found within a target executable. Additionally, the utility can find the chains of gadgets required to execute a given list of opcodes via ROP

- Multi-architecture support
- Pretty printing results
- Variable depth exploration

Building
========

The project depends on [capstone](https://github.com/aquynh/capstone). Additionally, [this](https://github.com/ithlony/Boost.Trie) trie implementation is included as a submodule. To build Rapport, clone this repository and execute `scons` from the project root.

Usage
=====

To see a list of available options, execute `rapport --help`. Below is a more complete description of the usage and effects of these options.

- `target` _filename_
    - File to search for ROP chains

- `input` _filename_
    - File containing instructions to be executed

- `base` _address_
    - address in hex which will be used as the starting point for all address output

- `pad` _bytes_
    - number of bytes to prepend to the raw output in the form of '~' characters. (this is useful for exploiting a stack overflow)

- `depth` _bytes_
    - number of bytes to examine for gadgets before each gadget-terminating opcode (i.e. retn, call, etc.)

- `arch` _architecture_
    - architecture of the target binary. Valid options are `X86`, `ARM`, `ARM64`, `PPC` and `MIPS`

- `mode` _mode_
    - mode of the target binary. Valid options are dependent on the architecture:
        - `X86`: `16`, `32` or `64`
        - `ARM`: `ARM` or `THUMB`
        - `ARM64`: `LE`
        - `PPC`: `32` or `64`
        - `MIPS`: `32` or `64`

- `verbose`
    - print all gadgets located, not just the ones needed

- `pprint`
    - Print addresses as strings rather than raw bytes

License
=======

This software is licensed under the Boost license. For more information, see the [license file](https://github.com/ALSchwalm/rapport/blob/master/LICENSE).
