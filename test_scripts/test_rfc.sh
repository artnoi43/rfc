#!/usr/bin/env bash

cargo r -- Cargo.lock -o e;
cargo r -- e -d -o d;
diff Cargo.lock d || echo "failed";
rm e d;