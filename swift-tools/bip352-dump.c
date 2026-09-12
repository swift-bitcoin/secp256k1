/* Dumps upstream's pre-processed BIP352 test vectors as JSON.
 *
 * src/modules/silentpayments/vectors.h is a nested C aggregate initialiser with
 * positional fields and fixed-size arrays. Parsing that with a regex would be
 * fragile in a way that fails silently, so the C compiler does the parsing
 * instead -- the same reasoning behind using clang's AST for the API notes.
 *
 * The upstream JSON (bip352_send_and_receive_test_vectors.json) cannot be used
 * directly: its `vin` entries are raw transaction inputs, so extracting the
 * input public keys needs Bitcoin script parsing (P2TR, P2WPKH, P2PKH,
 * P2SH-P2WPKH). vectors.h is upstream's own pre-processed form with those
 * already resolved, which is why upstream's C runner uses it too.
 *
 * Built and run by swift-tools/generate-bip352-vectors.py.
 */

#include <stdio.h>
#include <stddef.h>

#include "../src/modules/silentpayments/vectors.h"

static void hex(const unsigned char *data, size_t len) {
    size_t i;
    putchar('"');
    for (i = 0; i < len; i++) printf("%02x", data[i]);
    putchar('"');
}

/* `stride` is the declared row width and `len` the number of bytes to print.
 * They are passed separately and explicitly because the vectors mix row widths
 * -- 32, 33 and 64 -- and an array-typed parameter would silently fix the
 * stride at one of them, reading every row after the first from the wrong
 * offset. */
static void hex_array(const unsigned char *base, size_t count,
                      size_t stride, size_t len) {
    size_t i;
    putchar('[');
    for (i = 0; i < count; i++) {
        if (i) putchar(',');
        hex(base + i * stride, len);
    }
    putchar(']');
}

int main(void) {
    size_t v, i, j;
    printf("[\n");
    for (v = 0; v < SECP256K1_SILENTPAYMENTS_NUMBER_TESTVECTORS; v++) {
        const struct bip352_test_vector *t = &bip352_test_vectors[v];
        if (v) printf(",\n");
        printf(" {\n");

        printf("  \"plain_seckeys\": ");
        hex_array((const unsigned char *)t->plain_seckeys, t->num_plain_inputs, 32, 32);
        printf(",\n  \"plain_pubkeys\": ");
        hex_array((const unsigned char *)t->plain_pubkeys, t->num_plain_inputs, 33, 33);
        printf(",\n  \"taproot_seckeys\": ");
        hex_array((const unsigned char *)t->taproot_seckeys, t->num_taproot_inputs, 32, 32);
        printf(",\n  \"xonly_pubkeys\": ");
        hex_array((const unsigned char *)t->xonly_pubkeys, t->num_taproot_inputs, 32, 32);
        printf(",\n  \"outpoint_smallest\": ");
        hex(t->outpoint_smallest, 36);

        printf(",\n  \"num_outputs\": %zu", t->num_outputs);
        printf(",\n  \"recipients\": [");
        for (i = 0; i < t->num_recipient_entries; i++) {
            if (i) putchar(',');
            printf("\n   {\"scan_pubkey\": ");
            hex(t->recipient_pubkeys[i].scan_pubkey, 33);
            printf(", \"spend_pubkey\": ");
            hex(t->recipient_pubkeys[i].spend_pubkey, 33);
            printf(", \"count\": %zu}", t->recipient_pubkeys[i].count);
        }
        printf("\n  ]");

        /* Sending expectations: several permutations may be acceptable, because
         * BIP352 groups outputs per scan key. */
        printf(",\n  \"expected_output_sets\": [");
        for (i = 0; i < t->num_output_sets; i++) {
            if (i) putchar(',');
            printf("\n   ");
            hex_array((const unsigned char *)t->recipient_outputs[i], t->num_recipient_outputs, 32, 32);
        }
        printf("\n  ]");

        printf(",\n  \"receive_subtests\": [");
        for (i = 0; i < t->num_receive_subtests; i++) {
            const struct bip352_receive_subtest *r = &t->receive_subtests[i];
            if (i) putchar(',');
            printf("\n   {\n    \"scan_seckey\": ");
            hex(r->scan_seckey, 32);
            printf(",\n    \"spend_seckey\": ");
            hex(r->spend_seckey, 32);
            printf(",\n    \"to_scan_outputs\": ");
            hex_array((const unsigned char *)r->to_scan_outputs, r->num_to_scan_outputs, 32, 32);
            printf(",\n    \"labels\": [");
            for (j = 0; j < r->num_labels; j++) {
                if (j) putchar(',');
                printf("%u", r->label_integers[j]);
            }
            printf("],\n    \"full_check\": %zu", r->full_check);
            printf(",\n    \"found_output_pubkeys\": ");
            hex_array((const unsigned char *)r->found_output_pubkeys, r->num_found_output_pubkeys, 32, 32);
            printf(",\n    \"found_seckey_tweaks\": ");
            hex_array((const unsigned char *)r->found_seckey_tweaks, r->num_found_output_pubkeys, 32, 32);
            printf("\n   }");
        }
        printf("\n  ]\n }");
    }
    printf("\n]\n");
    return 0;
}
