#!/usr/bin/env bash

cargo r -- Cargo.lock -o e;
cargo r -- e -d -o d;
diff Cargo.lock d || echo "❌ UNEXPECTED DECRYPTION OUTPUT ❌\n\n\n";
rm e d;

cargo r -- Cargo.lock -z -o e;
cargo r -- e -d -z -o d;
diff Cargo.lock d || echo "❌ UNEXPECTED DECRYPTION OUTPUT ❌\n\n\n";
rm e d;