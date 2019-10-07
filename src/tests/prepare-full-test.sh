#!/bin/bash

set -e

src_dir="$(pwd)"
cd "${1}"

function make_ca() {
    rm -rf "pkgi/$1"
    mkdir -p "pki/$1"
    mkdir -p pki/issued_certs

    openssl genpkey -out pki/$1/ca_private.pem -algorithm RSA -pkeyopt rsa_keygen_bits:2048

    openssl req -key pki/$1/ca_private.pem -passin pass:"$ppwd" -new -x509 -days 36500 -out pki/$1/ca.pem -sha256 -subj "/C=DE/ST=CA/L=Saratoga/O=Excelfore/OU=OMA/CN=CA/emailAddress=pawel@excelfore.com"

    touch pki/$1/index.txt
    openssl x509 -in pki/$1/ca.pem -noout -serial | awk -F= '{print $2}' > pki/$1/serial
}

function make_cert() {

    cert="$1"
    cdir="pki/$cert"

    if test -d "$cdir"; then
        echo "CRT: re-using cert $cert"
        return
    fi

    echo "CRT: creating new cert $cert"

    pushd .

    mkdir -p "$cdir"
    cd "$cdir"

    cnf="$src_dir"/test_data/"$cert".conf

    openssl genpkey -out private.pem -algorithm RSA -pkeyopt rsa_keygen_bits:2048
    start=$(date -d '2 days ago' +'%y%m%d000000Z')
    openssl req -new -utf8 -nameopt multiline,utf8 -config "$cnf" -key private.pem -out cert.req
    openssl ca -batch -config "$cnf" -startdate $start -days 365 -out cert.pem -in cert.req

    openssl pkcs8 -topk8 -in private.pem -passout pass:angela -out private_enc.pem

    popd

}

rm -rf testdata
mkdir -p testdata
cd testdata

mkdir -p pki
make_ca ca
make_cert broker
make_cert client-grp1
