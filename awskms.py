from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_der_public_key
import boto3

AWS_KMS_KEYSPEC_EC = {
    "ECC_NIST_P256": {"class": ec.SECP256R1,
                      "supported_sign_alg": "sha256"},
    "ECC_NIST_P384": {"class": ec.SECP384R1,
                      "supported_sign_alg": "sha384"},
    "ECC_NIST_P521": {"class": ec.SECP521R1,
                      "supported_sign_alg": "sha512"},
    "ECC_SECG_P256K1": {"class": ec.SECP256K1,
                        "supported_sign_alg": "sha256"},
}


class AWSKMSEllipticCurvePrivateKey(ec.EllipticCurvePrivateKey):
    """ Implement an Elliptic Curve Private key using AWS KMS as the backend key manager.

    This class is meant to represent the Elliptic Curve private key for signing operations.
    The actual signing operation is passed to AWS KMS for the KeyId provided for initialization.

    The key's public key is available, but because the private key is held in an external service and
    cannot be exported, operations that need direct access to the private key will not work.
    Such methods raise `NotImplementedError`.

    AWS Credentials must be available using the normal methods (see documentation for the AWS CLI or `boto3` library).

    At minimum, using this key to sign data needs permission for `kms:Sign` for the KMS CMK.
    To get additional details about the key (such as key_size or curve), `kms:DescribeKey` must also be allowed.
    To get the public key, `kms:GetPublicKey` must be allowed.

    """

    def __init__(self, keyid):
        self.keyid = keyid
        self.publickey = None
        self.metadata = None

    def __repr__(self):
        return "<AWSKMSEllipticCurvePrivateKey: {}>".format(self.keyid)

    def _load(self):
        client = boto3.client('kms')
        response = client.describe_key(KeyId=self.keyid)
        self.metadata = response['KeyMetadata']
        self.key_spec = self.metadata['KeySpec']
        if not (self.metadata['KeySpec'].startswith("ECC") and
                self.metadata['KeyUsage'] == 'SIGN_VERIFY'):
            raise ValueError("AWS KMS KeySpec must be one of ECC types and KeyUsage must be SIGN_VERIFY")
        if not self.metadata['KeySpec'] in AWS_KMS_KEYSPEC_EC:
            raise ValueError("AWS KMS KeySpec not supported")

    @property
    def key_size(self) -> int:
        """ Return the key size (int) based on KeySpec class. """
        if self.metadata is None:
            self._load()
        return AWS_KMS_KEYSPEC_EC[self.metadata['KeySpec']]['class'].key_size

    def signer(self, signature_algorithm):
        raise NotImplementedError("AsymmetricSignatureContext is not supported for AWS KMS keys")

    def exchange(
            self, algorithm: ec.ECDH, peer_public_key: ec.EllipticCurvePublicKey
    ) -> bytes:
        # TODO: Implement Key Exchange Operation, returning a shared key (bytes)
        raise NotImplementedError("exchange is not yet supported")

    def public_key(self) -> ec.EllipticCurvePublicKey:
        if self.publickey is None:
            client = boto3.client('kms')
            response = client.get_public_key(KeyId=self.keyid)
            self.publickey = load_der_public_key(response['PublicKey'])
        return self.publickey

    def private_numbers(self) -> ec.EllipticCurvePrivateNumbers:
        """ The private key is held in an external service and cannot be exported. """
        raise NotImplementedError("private_numbers is not supported for AWS KMS keys")

    def private_bytes(
            self,
            encoding,
            format_,
            encryption_algorithm,
    ) -> bytes:
        """ The private key is held in an external service and cannot be exported. """
        raise NotImplementedError("private_bytes is not supported for AWS KMS keys")

    @property
    def curve(self):
        """ Return an instance of `cryptography.hazmat.primitives.asymmetric.ec.EllipticCurve` based on KeySpec. """
        if self.metadata is None:
            self._load()
        return AWS_KMS_KEYSPEC_EC[self.metadata['KeySpec']]['class']

    def sign(
            self,
            data: bytes,
            signature_algorithm: ec.EllipticCurveSignatureAlgorithm,
    ) -> bytes:
        """ Send data to AWS KMS to be signed, return signature.

        If key metadata has been loaded, support for signature_algorithm will be checked,
        raising ValueError if unsupported.  If metadata is not available, no check will be done.

        """
        # signature_algorithm.algorithm.name -> Example: "sha256" (str)
        signature_algorithm_lookup = {
            "sha256": "ECDSA_SHA_256",
            "sha384": "ECDSA_SHA_384",
            "sha512": "ECDSA_SHA_512"
        }
        try:
            if (self.metadata is not None and
                    signature_algorithm.algorithm.name !=
                    AWS_KMS_KEYSPEC_EC[self.metadata['KeySpec']]['supported_sign_alg']):
                raise ValueError("Requested Signature Algorithm is not supported by KeySpec [{} != {}]".format(
                    signature_algorithm.algorithm.name,
                    AWS_KMS_KEYSPEC_EC[self.metadata['KeySpec']]['supported_sign_alg']))
            sig_alg_str = signature_algorithm_lookup[signature_algorithm.algorithm.name]
        except KeyError:
            raise ValueError("Unknown Signature Algorithm: {}".format(signature_algorithm.algorithm.name))
        client = boto3.client('kms')
        sign_response = client.sign(KeyId=self.keyid, SigningAlgorithm=sig_alg_str, Message=data)
        # LOG.info("Signature: %s", sign_response['Signature'])
        return sign_response['Signature']
