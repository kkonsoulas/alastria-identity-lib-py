import json
from web3 import Web3
from hexbytes import HexBytes

from jwcrypto import jwk, jwt, jws
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from eth_utils.hexadecimal import decode_hex

from alastria_identity.types import (NetworkDid, JwtToken)


class TokenService:
    BASE_HEADER = {
        'alg': 'ES256K',
        'typ': 'JWT'
    }

    def __init__(self, private_key: str):
        private_key = self.remove_starting_hex_prefix(private_key)
        # Build a pyca/cryptography private key from the raw secp256k1
        # private key bytes (32-byte big-endian integer), then export
        # it as PKCS#8 PEM and let jwcrypto import from that PEM. This
        # avoids depending on python-ecdsa's PEM formatting changes.
        priv_bytes = bytes.fromhex(private_key)
        # Construct an EC private key using SECP256K1 curve.
        private_value = int.from_bytes(priv_bytes, byteorder="big")
        private_numbers = ec.derive_private_key(
            private_value, ec.SECP256K1(), default_backend()
        )
        pem = private_numbers.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        # jwcrypto can import PKCS#8 PEM bytes
        self.signing_key = jwk.JWK.from_pem(pem)
        self.algorithm = 'ES256K'

    def remove_starting_hex_prefix(self, hex_data: str):
        if hex_data.startswith('0x'):
            return hex_data[2:]
        return hex_data

    @staticmethod
    def create_did(network_did: NetworkDid) -> str:
        return (
            f"did:ala:{network_did.network}:{network_did.network_id}"
            f":{network_did.proxy_address}"
        )

    def sign_jwt(self, jwt_data: JwtToken) -> str:
        token = jwt.JWT(header=jwt_data.header,
                        claims=jwt_data.payload, algs=[self.algorithm])
        token.make_signed_token(self.signing_key)
        return token.serialize()

    def verify_jwt(self, jwt_data: str, raw_public_key: str) -> bool:
        try:
            # Build a cryptography public key from raw uncompressed
            # public key bytes (or raw x,y bytes). The input `raw_public_key`
            # is expected to be hex of the uncompressed EC point (0x04||X||Y)
            pub = decode_hex(raw_public_key)
            # If the public key is in raw (x||y) 64-byte form, accept that too
            if len(pub) == 64:
                x = int.from_bytes(pub[:32], byteorder="big")
                y = int.from_bytes(pub[32:], byteorder="big")
            elif len(pub) == 65 and pub[0] == 0x04:
                x = int.from_bytes(pub[1:33], byteorder="big")
                y = int.from_bytes(pub[33:65], byteorder="big")
            else:
                # Try to parse as a PEM/DER blob
                try:
                    verifying_key = jwk.JWK.from_pem(pub)
                except Exception:
                    raise
                else:
                    # Imported directly from PEM
                    jws_token = jws.JWS(jwt_data)
                    jws_token.deserialize(jwt_data)
                    jws_token.allowed_algs.extend([self.algorithm])
                    jws_token.verify(verifying_key, alg=self.algorithm)
                    return True

            public_numbers = ec.EllipticCurvePublicNumbers(
                x, y, ec.SECP256K1()
            )
            public_key = public_numbers.public_key(default_backend())
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            verifying_key = jwk.JWK.from_pem(pem)
            jws_token = jws.JWS(jwt_data)
            jws_token.deserialize(jwt_data)
            jws_token.allowed_algs.extend([self.algorithm])
            jws_token.verify(verifying_key, alg=self.algorithm)
            return True
        except jws.InvalidJWSSignature:
            return False

    @staticmethod
    def decode_jwt(jwt_data: str) -> dict:
        jws_token = jws.JWS(jwt_data)
        jws_token.deserialize(jwt_data)
        return {
            "header": jws_token.jose_header,
            "payload": json.loads(jws_token.objects.get('payload'))
        }

    @staticmethod
    def psm_hash(signed_jwt: str, did: str) -> HexBytes:
        return Web3.keccak(text=f'{signed_jwt}{did}')
