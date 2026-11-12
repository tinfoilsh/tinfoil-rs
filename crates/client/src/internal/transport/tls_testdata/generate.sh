#!/bin/sh
# Regenerates the certificates and keys in this directory. They exist only
# for the tests of the TLS transport mode: a private certificate authority
# that the tests trust explicitly, and server certificates for 127.0.0.1.
# Nothing here is trusted outside those tests.
#
# Requires OpenSSL 3.4 or later. Run from this directory.
set -eu

key() { openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out "$1"; }

ca() { # ca <name> <common name>
    key "$1.key.pem"
    openssl req -x509 -new -key "$1.key.pem" -out "$1.pem" -days 36500 -subj "/CN=$2" \
        -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign"
}

leaf() { # leaf <out> <key> <ca> <subjectAltName> [validity options]
    out=$1; leaf_key=$2; issuer=$3; san=$4; shift 4
    [ $# -gt 0 ] || set -- -days 36500
    printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\n' "$san" > ext.tmp
    openssl req -new -key "$leaf_key" -subj "/CN=test server" |
        openssl x509 -req -CA "$issuer.pem" -CAkey "$issuer.key.pem" -CAcreateserial \
            -extfile ext.tmp -out "$out" "$@"
    rm -f ext.tmp
}

ca ca "Test CA"
ca other_ca "Another Test CA"
key key_a.pem
key key_b.pem

leaf leaf_a.pem key_a.pem ca "IP:127.0.0.1,DNS:localhost"
leaf leaf_b.pem key_b.pem ca "IP:127.0.0.1,DNS:localhost"
leaf leaf_a_other_ca.pem key_a.pem other_ca "IP:127.0.0.1,DNS:localhost"
leaf leaf_a_wrong_name.pem key_a.pem ca "DNS:other.example"
leaf leaf_a_expired.pem key_a.pem ca "IP:127.0.0.1,DNS:localhost" \
    -not_before 20200101000000Z -not_after 20200102000000Z

# The authorities' keys are not needed again.
rm -f ca.key.pem other_ca.key.pem ca.srl other_ca.srl other_ca.pem
