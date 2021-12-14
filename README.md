certificate-test-python
=========================

Proof of concept of operating a Certificate Authority (CA) using Python

This proof of concept shows how one might use the Python [cryptography](https://github.com/pyca/cryptography)
package with an AWS KMS asymmetric Customer Master Key (CMK) to build and sign certificates using Python.

In theory, one might use this to operate a Certificate Authority (CA) that is backed by a key secured by AWS KMS.

The core of this concept is backed by the [awskms](awskms.py) module to build the `AWSKMSEllipticCurvePrivateKey` class
based on
[ec.EllipticCurvePrivateKey](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/#cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey)
.

This proof uses an ECC key, but an RSA key could also be used if a similar PrivateKey class were built out.

## Quick Start

Ensure that the AWS credentials are configured appropriately for the environment. See
the [AWS CLI User Guide](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html)
for details on how to do this.

#### Create the AWS KMS Key and set environment

```shell
aws kms create-key --description "Certificate Test Key for CA" \
    --key-usage SIGN_VERIFY --key-spec ECC_NIST_P384  # Other ECC specs may be used
aws kms create-alias --alias-name alias/certificate-test --target-key-id <ID or ARN>  # Optional
```

Once created, set the environment variable with the key ID (or full ARN).

```shell
export KEYID=1234abcd-12ab-34cd-56ef-1234567890ab  # Replace with your key ID
```

#### Install Dependencies

Install the required packages according to [`requirements.txt`](requirements.txt), optionally in a virtual environment.

```shell
python -m virtualenv venv
source venv/bin/activate
python -m pip install -r requirements.txt
```

#### Run Python to create the CA Certificate

AWS KMS does not hold X.509 certificates, only a private key. To build and sign the certificate,
run [`create_ca.py`](create_ca.py) to create a sample self-signed, CA certificate.

```shell
python create_ca.py
```

This will create a file `ca-out.pem` containing the X.509 certificate.

#### Create a private key, CSR, and have the CA sign it

Create a valid CSR using any available method. This is commonly done using OpenSSL as shown.

```shell
openssl req -new -newkey ec:<(openssl ecparam -name secp384r1) -keyout cert-key.pem -nodes -out cert-csr.pem
```

This will create (or overwrite) files `cert-key.pem` and `cert-csr.pem` in the current directory.

Run [`test_sign.py`](test_sign.py) to sign the certificate using the CA created earlier.

```shell
python test_sign.py
```

This will output the signed certificate `cert-out.pem`.

#### Verify Certificate

To finish the proof, verify that the certificate can be verified against the Certificate Authority using a commonly
available method, such as with OpenSSL.

```shell
$ openssl verify -CAfile ca-out.pem cert-out.pem
cert-out.pem: OK
```
