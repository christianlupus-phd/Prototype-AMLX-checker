
import logging
import datetime
import os
import random

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
# from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.asymmetric import padding, utils
# from cryptography.exceptions import InvalidSignature

import amlx_prototype
import amlx_prototype.cryptodata as cd

class Bootstrapper:
    def __init__(self, args):
        self.log = logging.getLogger("main.bootstrapper")
        self.__oneDay = datetime.timedelta(1,0,0)
        self.args = args
    
    def run(self):
        lcd = self.getLocalKeyInfrastructure()
        self.__createFmuVariants(lcd)
    
    def __generatePrivateKey(self):
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )

            return key

    """
        Create a CSR using a pre-existing private key

        The parameter subj must be set to a dictionary that represents the attributes of the certificate in the CSR.
        For example, one could use {'C': 'DE', 'CN': 'Foo'}.
    """
    def __createCSR(self, subj: dict, key: rsa.RSAPrivateKey) -> x509.CertificateSigningRequest:
        # Build a string like C=DE,CN=Foo
        attrs = ','.join([f'{k}={v}' for k,v in subj.items()])

        # Create the CSR itself and return it
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name.from_rfc4514_string(attrs)
            ).sign(key, hashes.SHA256())
        return csr
    
    def __signCSR(self,
                  csr: x509.CertificateSigningRequest,
                  caKey: rsa.RSAPrivateKey,
                  caCert: x509.Certificate|x509.CertificateSigningRequest,
                  days: int
                  ) -> x509.Certificate:
        # Initialize helpers
        builder = x509.CertificateBuilder()
        today = datetime.datetime.today()

        # Fill in the metadata from the CSR and set validity times
        builder = builder.subject_name(csr.subject).issuer_name(caCert.subject) \
            .not_valid_before(today) \
            .not_valid_after(today + (self.__oneDay * days)) \
            .public_key(csr.public_key()) \
            .serial_number(x509.random_serial_number())
        
        # Sign the CSR with the issuer private key to obtain the final certificate
        return builder.sign(private_key=caKey, algorithm=hashes.SHA256())
    
    """
        Generate a root CA.

        This will create a CSR with some hard-coded values in the attributes.
        These do not matter in the prototype but must be considered carefully in a production environment.
    """
    def __generateCA(self) -> cd.ChainLink:
        # Start with a new private key
        key = self.__generatePrivateKey()
        # The CSR can be build from the private key, add some hard coded attributes
        csr = self.__createCSR({
            'C': 'DE',
            'ST': 'Baden-Wuerttemberg',
            'CN': 'FMU-Tester'
        }, key)

        # Self-sign the CSR for 10 years
        cert = self.__signCSR(csr, key, csr, 3650)

        # Pack the certificate and private key into some common structure for handling 
        return self.ChainLink(key, cert)
    
    """
        Generate a certificate in the chain of trust issued from another chain link

        The subject must be built as a dict. See above at __createCSR for an example.
    """
    def __createCertChainLink(self, subject: dict, issuer: cd.ChainLink, days: int) -> cd.ChainLink:
            # Start with a private key
            key = self.__generatePrivateKey()
            # Create the CSR
            csr = self.__createCSR(subject, key)
            # Sign the CSR with the private key of the issuer to obtain the final certificate
            cert = self.__signCSR(csr, issuer.key, issuer.cert, days)
            # Pack all data into a new chain link
            return cd.ChainLink(key, cert)
    
    """
        Get the path name of the certificate.
        This takes the --output-base and --pki CLI parameters into account and augments them by the name of the certificate.
    """
    def __getCertPathName(self, certName: str) -> str:
        if self.args.pki is not None:
            # The PKI path was explicitly set
            return os.path.join(self.args.base[0], 'pki', certName)
        else:
            # Fall back to the base path
            return os.path.join(self.args.pki[0], certName)

    """
        Load a a single certificate from the HDD
        The name of the certificate needs to be provided as a parameter
    """
    def __loadCert(self, name: str) -> cd.ChainLink:
        base = self.__getCertPathName(name)
        return cd.ChainLink.load(base)
    
    """
        Store a certificate link object to the HDD
        The name of the stored certificate on disk can be customized.
    """
    def __storeCert(self, name: str, link: cd.ChainLink):
        base = self.__getCertPathName(name)
        os.makedirs(base, exist_ok=True)
        link.store(base)
    
    """
        Check if a certificate with given name is existing on the HDD and a corresponding private key is found
    """
    def __isCertExisting(self, name: str) -> bool:
        base = self.__getCertPathName(name)
        if not os.path.exists(base):
            return False
        
        if not os.path.exists(os.path.join(base, 'cert.pem')):
            return False
        if not os.path.exists(os.path.join(base, 'key.pem')):
            return False
        
        return True
    
    """
        This method checks if a certificate with a given name exists.
        If the certificate exists, the method returns the loaded certificate.
        If it is not loadable, a new certificate is generated and returned.
    """
    def __ensureCertLinkExists(self, name: str, subj: dict, issuer: cd.ChainLink, days: int) -> cd.ChainLink:
        if self.__isCertExisting(name):
            self.log.debug(f'Loading certificate chain link "%s" from disk', name)
            return self.__loadCert(name)
        else:
            self.log.debug(f'Creating certificate "%s"', name)
            link = self.__createCertChainLink(subj, issuer, days)

            self.log.debug('Storing created certificate chain link to disk')
            self.__storeCert(name, link)
            
            return link

    """
        Create a PKI or load it form the disk
        The attributes are hard-coded in this prototype
    """
    def __createTestPKI(self) -> cd.TestPKI:

        # Read or create root certificate
        if self.__isCertExisting('ca'):
            self.log.debug('Loading CA from disk')
            ca = self.__loadCert('ca')
        else:
            self.log.debug('Generating new CA')
            ca = self.__generateCA()

            self.log.debug('Storing CA to disk')
            self.__storeCert('ca', ca)

        # print(strCertificateChainLink(ca))

        # Read or create intermediate certificate
        im = self.__ensureCertLinkExists('im', {
            'C': 'DE',
            'ST': 'Baden-Wuerttemberg',
            'CN': 'FMU-Tester'
        }, ca, 3650)
        # print(strCertificateChainLink(im))

        # Read or create vendor certificate
        vendor = self.__ensureCertLinkExists('vendor', {
            'C': 'DE',
            'ST': 'Baden-Wuerttemberg',
            'O': 'EKS Intec',
            'CN': 'Research'
        }, im, 500)

        # Read or create leaf certificate
        fmuCert = self.__ensureCertLinkExists('fmu', {
            'C': 'DE',
            'ST': 'Baden-Wuerttemberg',
            'O': 'EKS Intec',
            'OU': 'Research',
            'CN': 'BouncingBall'
        }, vendor, 150)

        return cd.TestPKI(ca, [ca, im, vendor], fmuCert)

    """
        Get the data available on the local machine ready for signing and validating FMUs

        This filters all the private keys out that must not be available locally
    """
    def getLocalKeyInfrastructure(self) -> cd.LocalCryptographicData:
        pki = self.__createTestPKI()
        chain = [x.cert for x in pki.chain]
        return cd.LocalCryptographicData(pki.rootCert.cert, chain, pki.leafCert)
    
    def __createFmuVariants(self, crypto: cd.LocalCryptographicData):
        
        class FmuCallbackPluginBrokenFile (amlx_prototype.container.DefaultFmuSpoofPlugin):
            def __init__(self) -> None:
                super().__init__()
                self.randomData = random.randbytes(10)
            
            def getData(self, data: bytes) -> bytes:
                return super().getData(data) + self.randomData
        
        class FmuCallbackPluginSpoofedHash (FmuCallbackPluginBrokenFile):
            def __init__(self) -> None:
                super().__init__()
            
            def hashData(self, hash: cd.Hash, nominalData: bytes):
                data = self.getData(nominalData)
                return super().hashData(hash, data)

        if self.args.test_fmus is None:
            containerPath = os.path.join(self.args.base[0], 'fmus')
        else:
            containerPath = 
        os.makedirs(containerPath, exist_ok=True)

        amlx = amlx_prototype.container.AMLContainerBuilder(self.args.boilerplate_path)
        amlx.init()

        cases = (
            ('nominal_fmu.amlx', amlx_prototype.container.DefaultFmuSpoofPlugin()),
            ('broken_fmu.amlx', FmuCallbackPluginBrokenFile()),
            ('tampered_fmu.amlx', FmuCallbackPluginSpoofedHash())
        )

        for filename, plugin in cases:
            amlx.updateDTData(crypto, plugin)
            containerFullPath = os.path.join(containerPath, filename)
            amlx.createContainer(containerFullPath, plugin)
