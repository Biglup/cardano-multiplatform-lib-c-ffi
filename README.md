# Cardano Multiplatform Lib C Foreign Function Interface

This library provides a thin layer of a stable and portable C FFI API for the [Cardano Multiplatform Lib](https://github.com/dcSpark/cardano-multiplatform-lib) library allowing it to integrate with native libraries in other languages easily.

cbindgen --config cbindgen.toml --crate cardano-multiplatform-lib-c-ffi --output cardano-multiplatform-lib-c-ffi.h
