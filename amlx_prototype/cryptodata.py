from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.hazmat.primitives import hashes

import os

class CryptographyHelper:
    def __init__(self) -> None:
        pass

    def getPrivateKeyAsPEM(self, key: rsa.RSAPrivateKey) -> bytes:
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    def getPublicKeyAsPEM(self, key: rsa.RSAPublicKey) -> bytes:
        return key.public_bytes(encoding=serialization.Encoding.PEM)
    
    def getCertificateAsPEM(self, cert: x509.Certificate) -> bytes:
        return cert.public_bytes(encoding=serialization.Encoding.PEM)

"""
    Helper structure to combine key and certificate

    This is only to simplify handling in the Python script and reduce the overhead in writing.
"""
class ChainLink:
    def __init__(self, key: rsa.RSAPrivateKey, cert: x509.Certificate) -> None:
        self.key = key
        self.cert = cert
    
    """
        Get a string representation for debugging purposes.
        The output of the private key can be controlled via parameter
    """
    def getStr(self, printPrivateKey: bool = False) -> str:
        out = self.cert.public_bytes(serialization.Encoding.PEM).decode()
        if printPrivateKey:
            ch = CryptographyHelper()
            keyOut = ch.getPrivateKeyAsPEM(self.key).decode()
            out = f'{out}\n{keyOut}'
        return out

    """
        Store the link as PEM files to the HDD
        The basename defines a folder to be used for storing the crypto data.
        The certificate is saves in a file cert.pem in that folder and the key is named key.pem.
    """
    def store(self, baseName: str):
        def storeData(file, d: bytes):
            with open(os.path.join(baseName, file), 'w') as f:
                f.write(d.decode())
        
        ch = CryptographyHelper()

        storeData('key.pem', ch.getPrivateKeyAsPEM(self.key))
        storeData('cert.pem', ch.getCertificateAsPEM(self.cert))
        pass
        
    """
        Loads a chain link from the disk as stored by the store() method
    """
    @classmethod
    def load(cls, baseName: str) -> "ChainLink":
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

"""
    This class represents a hash and its metadata like the name of the hashing function and an implementation of it.
    It is mainly used to pass around combined information about hashes.
"""
class Hash:
    def __init__(self) -> None:
        # Use a default value for the hashing function as SHA256. Can be changed later as well.
        self.hashName = 'SHA256'
        # The hash is not yet calculated, so initialize the field anyway.
        self.hash = None

    """
        Get a Hash object to calculate hashes.
    """
    def getHasher(self) -> hashes.Hash:
        return hashes.Hash(self.getFunction())
    
    """
        Get a function that calculates the hash function.
        This is only needed for internal access to the function for the cryptography functions
    """
    def getFunction(self) -> hashes.HashAlgorithm:
        return getattr(hashes, self.hashName)()
    
    """
        Store the actual hash for a concrete data sample to the object
    """
    def setHash(self, hash: bytes):
        self.hash = hash

    """
        Get a hexadecimal representation of the hash as used by common tools on the console
    """
    def getText(self) -> str:
        return ''.join(['{0:02x}'.format(x) for x in self.hash])
