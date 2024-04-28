#!/bin/bash
if [ ! -z "$PROSPEROGO" ]; then
  export $PATH=$PROSPEROGO:$PATH
fi
export GOOS=prospero
export GOAMD64=v3
ninja clean > /dev/null 2>&1
cd daemon
go build -o daemon.elf
if [ $? -eq 0 ]; then
  cd ..
  cmake -G Ninja -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_TOOLCHAIN_FILE=$PS5SDK/cmake/toolchain-ps5.cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=1 .
  ninja
else
  cd ..
fi
