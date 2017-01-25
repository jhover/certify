#!/bin/bash
#
# Assumes top-level dirs  /ca /intermediate 
#
#
#


echo "Set root dirs in root/openssl.cnf and intermediate/openssl.cnf"

create_root_ca(){
 # Handle root CA
 echo "Making root CA"
 echo "Making directories..."
 mkdir -p root/private root/certs root/newcerts root/crl root/csr
 echo "Making root CA key..."
 openssl genrsa -aes256 -out root/private/ca.key.pem 4096
 chmod 400 root/private/ca.key.pem
 echo "Making index, serial, crlnumber files..."
 touch root/index.txt
 echo 1000 > root/serial
 echo 1000 > root/crlnumber
 echo "Making root CA request and cert..."
 openssl req -config root/openssl.cnf \
     -key root/private/ca.key.pem \
     -new -x509 -days 7300 -sha256 -extensions v3_ca \
     -out root/certs/ca.cert.pem
 chmod 444 root/certs/ca.cert.pem
 echo "Emitting CA certificate..."
 openssl x509 -noout -text -in root/certs/ca.cert.pem
 echo "Done."

}


create_intermediate_ca(){
 # Handle intermediate CA
 echo "Making directories..."
 mkdir -p intermediate/certs intermediate/crl intermediate/csr intermediate/newcerts intermediate/private
 chmod 700 intermediate/private
 echo "Making index, serial, crlnumber files..."
 touch intermediate/index.txt
 echo 1000 > intermediate/serial
 echo 1000 > intermediate/crlnumber
echo "Making intermediate CA key..."
 openssl genrsa -aes256 \
    -out intermediate/private/intermediate.key.pem 4096
 chmod 400 intermediate/private/intermediate.key.pem

echo "Making intermediate request..."

 openssl req -config intermediate/openssl.cnf -new -sha256 \
      -key intermediate/private/intermediate.key.pem \
      -out intermediate/csr/intermediate.csr.pem		

echo "Signing intermediate request, generating intermeidate..."
 openssl ca -config root/openssl.cnf -extensions v3_intermediate_ca \
      -days 3650 -notext -md sha256 \
      -in intermediate/csr/intermediate.csr.pem \
      -out intermediate/certs/intermediate.cert.pem
 chmod 444 intermediate/certs/intermediate.cert.pem																																		

echo "Emitting intermediate cert..."
 openssl x509 -noout -text \
      -in intermediate/certs/intermediate.cert.pem

echo "Verifying intermdiate cert..."
 openssl verify -CAfile root/certs/ca.cert.pem \
      intermediate/certs/intermediate.cert.pem
echo "Done."
}


create_cert_chain(){
 # Create cert chain file
echo "Creating cert chain..."
 cat intermediate/certs/intermediate.cert.pem \
    root/certs/ca.cert.pem > intermediate/certs/ca-chain.cert.pem
 chmod 444 intermediate/certs/ca-chain.cert.pem
echo "Done"
}

# Create a host certificate for this host
create_host_certificate(){
 hostname=`hostname -f`

 openssl req -config intermediate/openssl.cnf \
    -key intermediate/private/$hostname.key.pem \
      -new -sha256 -out intermediate/csr/$hostname.csr.pem

 openssl ca -config intermediate/openssl.cnf \
      -extensions server_cert -days 375 -notext -md sha256 \
      -in intermediate/csr/$hostname.csr.pem \
      -out intermediate/certs/$hostname.cert.pem

 chmod 444 intermediate/certs/$hostname.cert.pem

 openssl x509 -noout -text \
    -in intermediate/certs/$hostname.cert.pem

}


clean(){
	rm -f */certs/*.pem
 rm -f */private/*.pem	
rm -f */csr/*.pem
}


case "$1" in
createroot)
        create_root_ca
        RETVAL=$?
        ;;
createintermediate)
    create_intermediate_ca
    RETVAL=$?
        ;;
certchain)
    create_cert_chain
    RETVAL=$?
    ;;

hostcert)
    create_host_certificate
        RETVAL=$?
        ;;
usercert)
    create_user_certificate
        RETVAL=$?
        ;;
clean)
     clean
     RETVAL=$?
     ;;
*)
        echo $"Usage: $0 {createroot|createintermediate|certchain|hostcert|usercert|clean}"
        RETVAL=2
esac




