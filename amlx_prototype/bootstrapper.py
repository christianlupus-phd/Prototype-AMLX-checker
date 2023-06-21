
import logging
import datetime
import os
import random

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.hazmat.primitives import hashes

import amlx_prototype
import amlx_prototype.cryptodata as cd

"""
    This class helps to create a new PKI from scratch and some test containers
"""
class Bootstrapper:
    def __init__(self, args):
        self.log = logging.getLogger("main.bootstrapper")
        self.__oneDay = datetime.timedelta(1,0,0)
        self.args = args
    
    def run(self):
        self.log.info('Prepare the process by ensuring the PKI is present.')
        lcd = self.getLocalKeyInfrastructure()

        self.log.info('Create different containers with and without changed FMUs/hashes to test script')
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
            'CN': 'FMU-Tester Root'
        }, key)

        # Self-sign the CSR for 10 years
        cert = self.__signCSR(csr, key, csr, 3650)

        # Pack the certificate and private key into some common structure for handling 
        return cd.ChainLink(key, cert)
    
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
        if self.args.pki is None:
            # Fall back to the base path
            return os.path.join(self.args.base[0], 'pki', certName)
        else:
            # The PKI path was explicitly set
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
            'CN': 'FMU-Tester Immediate CA'
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
    
    """
        Prepare the test AMLX containers with different levels of issues included
    """
    def __createFmuVariants(self, crypto: cd.LocalCryptographicData):
        
        """
            This derived class does no longer copy the plain data of the FMU during saving but instead adds a few bytes at the ending.
            The hash is calculated as in the original class that uses the nominal FMU data.

            As a result, the AMLX will contain the original hash (and signature) but a changed FMU.
            This simulates a container that was broken during transport/packing.
        """
        class FmuCallbackPluginBrokenFile (amlx_prototype.container.DefaultFmuSpoofPlugin):
            def __init__(self) -> None:
                super().__init__()

                # Get some random data to be added to the FMU to simulate breaking it
                self.randomData = random.randbytes(16)
            
            def getData(self, data: bytes) -> bytes:
                return super().getData(data) + self.randomData
        
        """
            This class is augmenting the base class by altering the calculation of the hash.
            To calculate the hash, the actual data in the container is used.

            The AMLX container will contain a matching pair of FMU and hash.
            The signature is still calculated with the original FMU thus checking the FMU with cryptographical verification should still fail.
        """
        class FmuCallbackPluginSpoofedHash (FmuCallbackPluginBrokenFile):
            def __init__(self) -> None:
                super().__init__()
            
            def hashData(self, hash: cd.Hash, nominalData: bytes):
                # Instead of using the nominal data in the hashing, take the modified data for hashing
                data = self.getData(nominalData)
                return super().hashData(hash, data)

        # Syntactic sugar to use the correct path to put the FMUs inside and to the PKI
        if self.args.test_fmus is None:
            containerPath = os.path.join(self.args.base[0], 'fmus')
        else:
            containerPath = self.args.test_fmus[0]
        os.makedirs(containerPath, exist_ok=True)
        if self.args.pki is not None:
            pkiPath = self.args.pki[0]
        else:
            pkiPath = os.path.join(self.args.base[0], 'pki')

        # Create an AMLX builder and read the boilerplate AML file
        amlx = amlx_prototype.container.AMLContainerBuilder(self.args.boilerplate_path[0])
        amlx.init()

        # Define all cases to create: First entry is the filename in the output dir and second one is the corresponding plugin object
        # (subclass of DefaultFmuSpoofPlugin) to use
        cases = (
            ('nominal_fmu.amlx', amlx_prototype.container.DefaultFmuSpoofPlugin()),
            ('broken_fmu.amlx', FmuCallbackPluginBrokenFile()),
            ('tampered_fmu.amlx', FmuCallbackPluginSpoofedHash())
        )

        for filename, plugin in cases:
            self.log.debug('Prepare container file %s in memory', filename)
            # Update the internal AML structures in memory
            amlx.updateDTData(crypto, plugin)

            # Store the data in a AMLX container
            containerFullPath = os.path.join(containerPath, filename)
            self.log.debug('Storing complete container to "%s"', containerFullPath)
            amlx.createContainer(containerFullPath, pkiPath, plugin)

            if self.args.output_inner_aml:
                amlFilename = f'{containerFullPath}.aml'
                self.log.debug('Writing inner AML file to %s for debugging purposes.', amlFilename)
                amlx.writePureAMLFile(amlFilename)
