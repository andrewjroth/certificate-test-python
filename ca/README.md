# Certificate Authority (CA)

These files are generally what are used by OpenSSL when operating a root CA. They should be used as a reference when
testing the operation of a CA that does not use OpenSSL.

## Important OpenSSL Commands

Here are some highlights of the commands needed to set up and operate a Certificate Authority (CA) using the OpenSSL
CLI.[^1]

#### Setup directories and files

```shell
mkdir private certs crl
touch index.txt
echo 1000 > serial
echo 1000 > crl/crlnumber
```

The OpenSSL configuration is contained in [openssl_root.conf](openssl_root.conf).

#### Create the Root CA private key and certificate

```shell
openssl ecparam -genkey -name secp384r1 | openssl ec -out private/ca.key.pem
openssl req -config openssl_root.conf -new -x509 -sha384 -extensions v3_ca -key private/ca.key.pem -out certs/ca.crt.pem
openssl x509 -noout -text -in certs/ca.crt.pem  # View Certificate Details
```

The important X.509 v3 extension attributes defined within the `openssl_root.conf` for a CA are:

```shell
X509v3 Basic Constraints: critical
    CA:TRUE
X509v3 Key Usage: critical
    Digital Signature, Certificate Sign, CRL Sign
```

#### Generate the CRL

```shell
openssl ca -config openssl_root.conf -gencrl -out crl/root.crl
```

#### Generate a Private Key and Certificate Signing Request (CSR)

This is typically done by a remote user, not as part of the CA.  
The user will provide the CSR to the CA to be signed.

```shell
openssl ecparam -genkey -name secp384r1 | openssl ec -out private/example.key.pem
openssl req -new -sha384 -extensions v3_ca -key private/example.key.pem -out certs/example.csr.pem
```

Along with the CSR, the request should include desired Subject Alternative Name (SAN) attributes as these are now
required by browsers. With OpenSSL, SAN attribute can only be specified in a configuration file and only one
configuration file may be specified on the command line. Therefore, this information should be added to a copy of the
configuration file being used for the signing certificate.

Example `openssl_server.conf` for a Server Certificate:

```shell
[ server_cert ]
subjectAltName = @alt_names

[alt_names]
DNS.0 = webby.example.com
```

Note that the value for `DNS.0` must match the certificate's Subject `CN` field.

#### Sign the Certificate Signing Request (CSR)

With the CSR saved as `certs/example.csr.pem` and the `subjectAltName` attribute defined in `openssl_server.conf`:

```shell
openssl ca -config openssl_server.cnf -extensions server_cert -days 30 -in certs/example.csr.pem -out certs/example.crt.pem
openssl x509 -noout -text -in certs/example.crt.pem  # View Certificate Details
```

The important X.509 v3 extension attributes to review for a server certificate are:

```shell
        X509v3 extensions:
            X509v3 Basic Constraints:
                CA:FALSE
            Netscape Cert Type:
                SSL Server
            ...
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage:
                TLS Web Server Authentication
            ...
            X509v3 Subject Alternative Name:
                DNS:webby.example.com
```

#### Verify the certificate against the CA

This verification using OpenSSL should work regardless of how the CA certificate or the certificate being validated was
created. Importantly, **_this validation should be used to validate how a CA that is not using the OpenSSL CLI is
operating_**.

```shell
openssl verify -CAfile certs/ca.crt.pem certs/example.crt.pem

certs/example.crt.pem: OK
```

## References

[^1]: [F5 dev/central - Building an OpenSSL Certificate Authority](https://devcentral.f5.com/s/articles/building-an-openssl-certificate-authority-introduction-and-design-considerations-for-elliptical-curves-27720)
Originally posted November 06, 2017; retrieved Dec 13, 2021.
