from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.hazmat.primitives import hashes

import os

class CryptographyHelper:
    def __init__(self) -> None:
        pass

    def __getPrivateKeyAsPEM(self, key: rsa.RSAPrivateKey) -> bytes:
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    def __getPublicKeyAsPEM(self, key: rsa.RSAPublicKey) -> bytes:
        return key.public_bytes(encoding=serialization.Encoding.PEM)
    
    def __getCertificateAsPEM(self, cert: x509.Certificate) -> bytes:
        return cert.public_bytes(encoding=serialization.Encoding.PEM)

"""
    Helper structure to combine key and certificate

    This is only to simplify handling in the Python script and reduce the overhead in writing.
"""
class ChainLink:
    def __init__(self, key: rsa.RSAPrivateKey, cert: x509.Certificate) -> None:
        self.key = key
        self.cert = cert
    
    def getStr(self, printPrivateKey: bool = False) -> str:
        out = self.cert.public_bytes(serialization.Encoding.PEM).decode()
        if printPrivateKey:
            ch = CryptographyHelper()
            keyOut = ch.__getPrivateKeyAsPEM(self.key).decode()
            out = f'{out}\n{keyOut}'
        return out

    def store(self, baseName: str):
        def storeData(file, d: bytes):
            with open(os.path.join(baseName, file), 'w') as f:
                f.write(d.decode())
        
        ch = CryptographyHelper()

        storeData('key.pem', ch.__getPrivateKeyAsPEM(self.key))
        storeData('cert.pem', ch.__getCertificateAsPEM(self.cert))
        pass
        
    @classmethod
    def load(baseName: str) -> "ChainLink":
        def loadData(file):
            with open(os.path.join(baseName, file), 'r') as f:
                return f.read().encode()
        
        keyData = loadData('key.pem')
        certData = loadData('cert.pem')

        return ChainLink(
            serialization.load_pem_private_key(keyData, password=None),
            x509.load_pem_x509_certificate(certData)
        )
        pass

"""
    All cryptographic data collected and structured for simpler handling

    This covers both public certificates and private keys of the complete chain.
"""    
class TestPKI:
    def __init__(self, rootCert: ChainLink, chain: list[ChainLink], leafCert: ChainLink) -> None:
        self.rootCert = rootCert
        self.chain = chain
        self.leafCert = leafCert

"""
    All cryptographic data present on the machine that generates the FMUs

    This only contains the public certificates and the private key of the leaf certificate.
    This can be considered the same data that is needed in order to sign and validate FMUs/AMLX containers.
"""
class LocalCryptographicData:
    def __init__(self, rootCert: x509.Certificate, chain: list[x509.Certificate], leafCert: ChainLink) -> None:
        self.rootCert = rootCert
        self.chain = chain
        self.leafCert = leafCert

class Hash:
    def __init__(self) -> None:
        self.hashName = 'SHA256'
        self.hashFunction = hashes.SHA256()
        self.hash = None

    # @classmethod
    # def load()

    def getHasher(self) -> hashes.Hash:
        return hashes.Hash(self.hashFunction)
    
    def setHash(self, hash: bytes):
        self.hash = hash

    def getText(self) -> str:
        return ''.join(['{0:02x}'.format(x) for x in self.hash])
