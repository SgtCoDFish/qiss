#!/usr/bin/env bash

set -eu -o pipefail

LIBOQS_INCLUDE_DIR=`pwd`/bin/liboqs/build/include
LIBOQS_LIB_DIR=`pwd`/bin/liboqs/build/lib

cat << EOF
Name: liboqs
Description: C library for quantum resistant cryptography
Version: 0.5.0-dev
Cflags: -I${LIBOQS_INCLUDE_DIR}
Ldflags: '-extldflags "-Wl,-stack_size -Wl,0x1000000"'
Libs: -L${LIBOQS_LIB_DIR} -loqs
EOF
