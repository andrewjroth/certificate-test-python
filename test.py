from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
import os

from awskms import AWSKMSEllipticCurvePrivateKey

# Insert Key or Alias ARN, such as:
# arn:aws:kms:us-east-1:123456789012:alias/ca-signing-key
KEYID = os.environ.get("KEYID")

with open('cert-csr.pem') as infile:
    csr = x509.load_pem_x509_csr(bytes(infile.read(), encoding='UTF-8'))

builder = x509.CertificateBuilder().issuer_name(
    x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u'Test CA')])
).subject_name(
    csr.subject
).public_key(
    csr.public_key()
).serial_number(
    1
).not_valid_before(
    datetime.today()
).not_valid_after(
    datetime.today() + timedelta(days=30)
)
cert = builder.sign(AWSKMSEllipticCurvePrivateKey(KEYID), hashes.SHA384())
with open('cert-out.pem', 'wb') as outfile:
    outfile.write(cert.public_bytes(Encoding.PEM))
