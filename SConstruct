import os
import fnmatch
import platform

BIN_NAME = ARGUMENTS.get('BIN_NAME', 'rapport')
CXX = ARGUMENTS.get('CXX', 'g++')
BUILD_PATH = ARGUMENTS.get('BUILD', "build/")

env = Environment(CXX=CXX, ENV = os.environ)

env.Append(CXXFLAGS=['-Wall', '-Wextra', '-std=c++11'])
env.Append(CPPPATH=['include', 'include/Boost.Trie'])
env.Append(LIBS=["boost_program_options"])

def create_objs(SRCS):
    return [env.Object(src) for src in SRCS]


src_list = []
for root, dirnames, filenames in os.walk('src/'):
    for filename in fnmatch.filter(filenames, '*.cpp'):
        src_list.append(os.path.join(root, filename))

if platform.system() == "Windows":
    env.Program(target = BUILD_PATH + BIN_NAME + ".exe", source = create_objs(src_list))
elif platform.system() == "Linux":
    env.Program(target =BUILD_PATH + BIN_NAME, source = create_objs(src_list))
