/* Shim TU for upstream's `noverify_tests` binary (CMake: add_executable_and_tests(noverify_tests "")).
 *
 * Upstream compiles src/tests.c twice, with and without VERIFY. SwiftPM refuses
 * to put one file in two targets, so each variant gets its own one-line TU and
 * the defines are supplied by Package.swift.
 *
 * src/tests.c #includes secp256k1.c itself, so this must NOT link CSECP256K1.
 * It does not include the precomputed tables, hence those below -- matching
 * CMake's `target_link_libraries(tests secp256k1_precomputed ...)`.
 *
 * Quoted #includes resolve relative to the including file, so the nested
 * includes inside tests.c still resolve against src/. */
#include "../../src/tests.c"
#include "../../src/precomputed_ecmult.c"
#include "../../src/precomputed_ecmult_gen.c"
