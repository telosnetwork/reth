#!/bin/bash

INSTALL_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
OG_DIR="$(pwd)"

cargo build --bin telos-reth --features telos --release --manifest-path crates/telos/bin/Cargo.toml

cd $OG_DIR
