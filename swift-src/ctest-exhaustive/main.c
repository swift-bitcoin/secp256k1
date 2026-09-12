/* Shim TU for upstream's `exhaustive_tests` binary.
 *
 * Note the asymmetry with the other suites: CMake links this one against
 * secp256k1_asm ONLY, with an explicit comment "do not include
 * secp256k1_precomputed in exhaustive_tests (it uses runtime-generated
 * tables)". src/tests_exhaustive.c pulls in ecmult_compute_table_impl.h and
 * builds its tables at runtime, so including the precomputed ones here would
 * be a duplicate-symbol error.
 *
 * Like tests.c, it #includes secp256k1.c, so it must NOT link CSECP256K1. */
#include "../../src/tests_exhaustive.c"
