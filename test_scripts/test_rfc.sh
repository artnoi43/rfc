#!/usr/bin/env bash

cargo r -- Cargo.lock -o e;
cargo r -- e -d -o d;
diff Cargo.lock d || echo "❌ UNEXPECTED DECRYPTION OUTPUT ❌\n\n\n";
rm e d;

cargo r -- Cargo.lock -z -o e;
cargo r -- e -d -z -o d;
diff Cargo.lock d || echo "❌ UNEXPECTED DECRYPTION OUTPUT ❌\n\n\n";
rm e d;

cargo r -- Cargo.lock -e b64 -o e;
cargo r -- e -d -e b64 -o d;
diff Cargo.lock d || echo "❌ UNEXPECTED DECRYPTION OUTPUT ❌\n\n\n";
rm e d;

cargo r -- Cargo.lock -z -e b64 -o e;
cargo r -- e -d -z -e b64 -o d;
diff Cargo.lock d || echo "❌ UNEXPECTED DECRYPTION OUTPUT ❌\n\n\n";
rm e d;

cargo r -- Cargo.lock -e hex -o e;
cargo r -- e -d -e hex -o d;
diff Cargo.lock d || echo "❌ UNEXPECTED DECRYPTION OUTPUT ❌\n\n\n";
rm e d;

cargo r -- Cargo.lock -z -e hex -o e;
cargo r -- e -z -d -e hex -o d;
diff Cargo.lock d || echo "❌ UNEXPECTED DECRYPTION OUTPUT ❌\n\n\n";
rm e d;