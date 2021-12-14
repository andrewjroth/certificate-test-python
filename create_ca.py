from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, load_der_public_key
import os
import boto3

from awskms import AWSKMSEllipticCurvePrivateKey

# Insert Key or Alias ARN, such as:
# arn:aws:kms:us-east-1:123456789012:alias/ca-signing-key
KEYID = os.environ.get("KEYID")

client = boto3.client('kms')
response = client.get_public_key(KeyId=KEYID)
publickey = load_der_public_key(response['PublicKey'])

builder = x509.CertificateBuilder().issuer_name(
    x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u'Test CA')])
).subject_name(
    x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u'Test CA')])
).public_key(
    publickey
).serial_number(
    1
).not_valid_before(
    datetime.today()
).not_valid_after(
    datetime.today() + timedelta(days=30)
).add_extension(
    x509.BasicConstraints(ca=True, path_length=0), critical=True
).add_extension(
    x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False
    ), critical=True
)
cert = builder.sign(AWSKMSEllipticCurvePrivateKey(KEYID), hashes.SHA384())
with open('ca-out.pem', 'wb') as outfile:
    outfile.write(cert.public_bytes(Encoding.PEM))
