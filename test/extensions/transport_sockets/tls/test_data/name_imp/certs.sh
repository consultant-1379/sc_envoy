#!/bin/bash

set -e

readonly DEFAULT_VALIDITY_DAYS=${DEFAULT_VALIDITY_DAYS:-730}
HERE=$(cd "$(dirname "$0")" && pwd)
readonly HERE

cd "$HERE" || exit 1
trap cleanup EXIT

cleanup() {
    rm ./*csr
    rm ./*srl
    rm ./crl_*
    rm ./intermediate_crl_*
}

# $1=<CA name> $2=[issuer name]
generate_ca() {
    local extra_args=()
    if [[ -n "$2" ]]; then
        extra_args=(-CA "${2}_cert.pem" -CAkey "${2}_key.pem" -CAcreateserial);
    else
        extra_args=(-signkey "${1}_key.pem");
    fi
    openssl genrsa -out "${1}_key.pem" 2048
    openssl req -new -key "${1}_key.pem" -out "${1}_cert.csr" -config "${1}_cert.cfg" -batch -sha256
    openssl x509 -req -days "${DEFAULT_VALIDITY_DAYS}" -in "${1}_cert.csr" -out "${1}_cert.pem" \
            -extensions v3_ca -extfile "${1}_cert.cfg" "${extra_args[@]}"
    generate_info_header "$1"
}

# $1=<certificate name> $2=[key size] $3=[password]
generate_rsa_key() {
    local keysize extra_args=()
    keysize="${2:-2048}"
    if [[ -n "$3" ]]; then
        echo -n "$3" > "${1}_password.txt"
        extra_args=(-aes128 -passout "file:${1}_password.txt")
    fi
    openssl genrsa -out "${1}_key.pem" "${extra_args[@]}" "$keysize"
}

# $1=<certificate name> $2=[curve]
generate_ecdsa_key() {
    local curve
    curve="${2:-secp256r1}"
    openssl ecparam -name "$curve" -genkey -out "${1}_key.pem"
}

# $1=<certificate name>
generate_info_header() {
    local prefix
    prefix="TEST_$(echo "$1" | tr '[:lower:]' '[:upper:]')"
    {
        echo "// NOLINT(namespace-envoy)"
        echo "constexpr char ${prefix}_CERT_256_HASH[] ="
        echo "    \"$(openssl x509 -in "${1}_cert.pem" -outform DER | openssl dgst -sha256 | cut -d" " -f2)\";"
        echo "constexpr char ${prefix}_CERT_1_HASH[] = \"$(openssl x509 -in "${1}_cert.pem" -outform DER | openssl dgst -sha1 | cut -d" " -f2)\";"
        echo "constexpr char ${prefix}_CERT_SPKI[] = \"$(openssl x509 -in "${1}_cert.pem" -noout -pubkey | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | openssl enc -base64)\";"
        echo "constexpr char ${prefix}_CERT_SERIAL[] = \"$(openssl x509 -in "${1}_cert.pem" -noout -serial | cut -d"=" -f2 | awk '{print tolower($0)}')\";"
        echo "constexpr char ${prefix}_CERT_NOT_BEFORE[] = \"$(openssl x509 -in "${1}_cert.pem" -noout -startdate | cut -d"=" -f2)\";"
        echo "constexpr char ${prefix}_CERT_NOT_AFTER[] = \"$(openssl x509 -in "${1}_cert.pem" -noout -enddate | cut -d"=" -f2)\";"
    } > "${1}_cert_info.h"
}

# $1=<certificate name> $2=<CA name> $3=[days]
generate_x509_cert() {
    local days extra_args=()
    days="${3:-${DEFAULT_VALIDITY_DAYS}}"
    if [[ -f "${1}_password.txt" ]]; then
        extra_args=(-passin "file:${1}_password.txt")
    fi
    openssl req -new -key "${1}_key.pem" -out "${1}_cert.csr" -config "${1}_cert.cfg" -batch -sha256 "${extra_args[@]}"
    openssl x509 -req -days "$days" -in "${1}_cert.csr" -sha256 -CA "${2}_cert.pem" -CAkey \
            "${2}_key.pem" -CAcreateserial -out "${1}_cert.pem" -extensions v3_ca -extfile "${1}_cert.cfg" "${extra_args[@]}"
    generate_info_header "$1"
}

# $1=<certificate name> $2=<CA name> $3=[days]
#
# Generate a certificate without a subject CN. For this to work, the config
# must have an empty [req_distinguished_name] section.
generate_x509_cert_nosubject() {
    local days
    days="${3:-${DEFAULT_VALIDITY_DAYS}}"
    openssl req -new -key "${1}_key.pem" -out "${1}_cert.csr" -config "${1}_cert.cfg" -subj / -batch -sha256
    openssl x509 -req -days "$days" -in "${1}_cert.csr" -sha256 -CA "${2}_cert.pem" -CAkey \
            "${2}_key.pem" -CAcreateserial -out "${1}_cert.pem" -extensions v3_ca -extfile "${1}_cert.cfg"
    generate_info_header "$1"
}

# $1=<certificate name> $2=[certificate file name]
generate_selfsigned_x509_cert() {
    local output_prefix
    output_prefix="${2:-$1}"
    openssl req -new -x509 -days "${DEFAULT_VALIDITY_DAYS}" -key "${1}_key.pem" -out "${output_prefix}_cert.pem" -config "${1}_cert.cfg" -batch -sha256
    generate_info_header "$output_prefix"
}

# $1=<CA name>
# Generates a chain of 3 intermediate certs in test_long_cert_chain
# and a cert signed by this in test_random_cert.pem
generate_cert_chain() {
    local certname
    local ca_name="${1}"
    rm test_long_cert_chain.pem
    touch test_long_cert_chain.pem
    for x in {1..4}; do
        certname="i$x"
        if [[ $x -gt 1 ]]
        then
            ca_name="i$((x - 1))"
        fi
        echo "$x: $certname $ca_name"
        generate_ca $certname $ca_name
    done
    for x in {1..3}; do
        cat "i${x}_cert.pem" >> test_long_cert_chain.pem
    done
    mv i4_cert.pem test_random_cert.pem
}

# Generate ca_cert
generate_ca ca1
generate_ca ca2

# Concatenate ca1 and ca2 to create CA file with multiple entries.
cat ca1_cert.pem ca2_cert.pem > ca_comb.pem

# Generate cert for RP_1
generate_rsa_key rp_1
generate_x509_cert rp_1 ca1

# Generate cert for RP_2
generate_rsa_key rp_2
generate_x509_cert rp_2 ca2

#Generate cert for RP_2 impersonate RP_1
generate_rsa_key rp_2_imp_1
generate_x509_cert rp_2_imp_1 ca2

# Generate expired_cert.pem as a self-signed, expired cert (will fail on macOS 10.13+ because of negative days value).
cp -f rp_2_cert.cfg expired_cert.cfg
generate_rsa_key expired
generate_x509_cert expired ca2 -365
rm -f expired_cert.cfg

generate_ca intermediate_ca ca2

cp -f rp_2_cert.cfg rp_2_signed_by_intermediate_cert.cfg
generate_rsa_key rp_2_signed_by_intermediate
generate_x509_cert rp_2_signed_by_intermediate intermediate_ca
rm -f rp_2_signed_by_intermediate_cert.cfg