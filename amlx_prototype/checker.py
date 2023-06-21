
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.exceptions import InvalidSignature

import datetime
import zipfile
import re
import logging

from bs4 import BeautifulSoup, Tag

import amlx_prototype.cryptodata as cd

"""
    This class provides functionality to check an AMLX container for validity
"""
class Checker:
    def __init__(self, args) -> None:
        self.__args = args
        self.log = logging.getLogger('main.checker')
        self.testFailed = False

    """
        The main entry point.
    """
    def run(self):
        # Read the container
        fmu = self.__parseAMLXContainer(self.__args.file[0])

        if self.testFailed:
            # This is only needed in case --force is given
            self.log.fatal('Some tests have failed. Aborting here.')
            exit(1)

        self.log.info('The FMU was successfully validated. It can be used for simulation.')

        # Output the embedded FMU if requested by the user
        if not self.__args.test_only:
            self.__storeFMUToFile(fmu)

    """
        Handle problems in a common manner
        
        This is called if the FMU cannot be trusted
    """
    def __reportFailedTest(self, *args, **kwargs):
        self.log.fatal(*args, **kwargs)
        self.testFailed = True

        if not self.__args.force:
            exit(1)
    
    """
        Parse the container and return the FMU embedded
    """
    def __parseAMLXContainer(self, fileName) -> bytes:
        self.log.debug('Importing file %s', fileName)
        with zipfile.ZipFile(fileName, 'r') as zf:
            # Obtain the name of the AML file inside the container
            rootFileName = self.__getRootFilename(zf)
            self.log.debug('Found root AML filename "%s"', rootFileName)

            # Read the data from the AML file, check the FMU and return it
            return self.__parseRootAMLFile(zf, rootFileName)
    
    """
        Fix the name of paths

        Inside the container all files are referenced absolutely with a beginning slash (/).
        This method just chops that of to simplify access to files
    """
    def __fixPathName(self, path: str) -> str:
        return re.sub('^/*', '', path)

    """
        Get the name of the root AML file

        This is stored in the _rels/.rels XML file.
    """
    def __getRootFilename(self, zf: zipfile.ZipFile):
        relData = zf.read('_rels/.rels')
        soup = BeautifulSoup(relData, 'xml')
        # Find the corresponding entry for the root AML file
        rel = soup.find('Relationship', Type='http://schemas.automationml.org/container/relationship/RootDocument')
        target = rel['Target']
        
        return self.__fixPathName(target)

    """
        Helper to fetch entries within the AML tree

        This allows to find one or all entries with a given "Name" attribute within an XML tag.
        This simplifies writing and avoid duplicate code.
    """
    def __find(self,parent, type, name, all=False):
        if all:
            return parent.find_all(type, attrs={'Name': name})
        else:
            return parent.find(type, attrs={'Name': name})

    """
        Get the name of the FMU within the container

        The suc parameter is the SystemUnitClass to be analyzed.
    """
    def __getFmuFilename(self, suc: Tag) -> str:
        name = self.__find(
            suc.find('ExternalInterface', RefBaseClassPath="AutomationMLFMIInterfaceClassLib/FMIReference"),
            'Attribute', 'refURI'
        ).Value.string
        return self.__fixPathName(name)

    """
        Get the parameters from the AML regarding the hashing used during building
    """
    def __getHashParams(self, suc: Tag):
        hashType = self.__find(suc, 'Attribute', 'hashType').Value.string
        hashValueText = self.__find(suc, 'Attribute', 'hashValue').Value.string
        hashValue = bytes.fromhex(hashValueText)        

        hash = cd.Hash()
        hash.hashName = hashType
        hash.setHash(hashValue)

        return hash

    """
        Get the hashing used for the signature

        If no hash is present in the container, a best effort guess is made.
        This is only implemented very roughly

        This method returns a Hash object initialized with the correct hash function
    """
    def __guessHashFunction(self, suc: Tag) -> cd.Hash:
        tag = self.__find(suc, 'Attribute', 'hashType')
        if tag is not None and tag.Value is not None:
            hash = cd.Hash()
            hash.hashName = tag.Value.string
            return hash
        else:
            hash = cd.Hash()
            return hash

    """
        This calculates the hash of a data stream

        It allows to set the hash method using the provided Hash object.
        Note that the object's hash content gets updated.
    """
    def __calculateHashOfFile(self, data: bytes, hash: cd.Hash):
        digest = hashes.Hash(hash.getFunction())
        digest.update(data)
        raw = digest.finalize()

        hash.setHash(raw)

        self.log.debug('Calculated hash of the actual data: %s', hash.getText())

        return hash
        
    """
        Check if the hash provided in the AML file matches with the hash of the embedded FMU file

        The hashOfFile must be the Hash object of the embedded FMU
    """
    def __checkInternalHash(self, suc: Tag, hashOfFile: cd.Hash):
        # Get the hash type to be sure to use the same method
        hashInAML = self.__getHashParams(suc)

        textInAML = hashInAML.getText()
        textOfFile = hashOfFile.getText()

        self.log.debug('Comparing hash in AMLX container (%s) with hash of embedded FMU file (%s)', textInAML, textOfFile)
        if textInAML == textOfFile:
            self.log.debug('Hash matches')
        else:
            self.__reportFailedTest('The hash in the AMLX container does not match the hash of the embedded FMU file.')

    """
        Get the certificate chain as declared in AML

        The certificate chain is not ordered in AML but instead linked via directed edges.
        This method follows the edges and builds a sorted list of the certificates
    """
    def __parseCertificateChainInAML(self, suc: Tag) -> list[Tag]:
        
        # Check if a certificate entry in the AML denotes a root certificate
        def isRootCertificate(certTag: Tag) -> bool:
            rr = certTag.find('RoleRequirements', RefBaseRoleClassPath="SecurityRoleClassLib/RootCertificate")
            return rr is not None
        
        # Follow the links to obtain the issuer certificate entry in AML
        def getIssuingCertificateTag(certTag: Tag) -> Tag:
            # Get the AML ID of the ExternalInterface entry of the current certificate
            issuerCertificateExternalLinkId = certTag.find('ExternalInterface', RefBaseClassPath="SecurityInterfaceLib/IssuerCertificate", recursive=False)['ID']
            # Find the corresponding InternalLink element
            internalLink = suc.find('InternalLink', RefPartnerSideB=issuerCertificateExternalLinkId)
            # Get the AML ID of the ExternalInterface entry of the corresponding issuer certificate
            issuedCertificateExternalLinkId = internalLink['RefPartnerSideA']
            # Return the issuer certificate entry in AML
            return suc.find(ID=issuedCertificateExternalLinkId).parent

        # Start with the leaf certificate
        leaf = suc.find('RoleRequirements', RefBaseRoleClassPath='SecurityRoleClassLib/LeafCertificate').parent
        self.log.debug('Leaf certificate id: %s', leaf['ID'])

        # Initialize the algorithm
        cert = leaf
        chain = [leaf]

        while(not isRootCertificate(cert)):
            # ... the current certificate is not (yet) a root certificate
            self.log.debug('Certificate %s (ID %s) is no root certificate. Continuing', cert['Name'], cert['ID'])
            # Obtain the issuer and add it to the chain
            cert = getIssuingCertificateTag(cert)
            chain.append(cert)
            self.log.debug("Found issuer certificate %s (ID %s)", cert['Name'], cert['ID'])
        
        self.log.debug('Found certificate chain: %s', [x['Name'] for x in chain])
        self.log.debug('Subjects" %s', [self.__find(x, 'Attribute', 'Subject').Value.string for x in chain])
        return chain

    """
        Load the certificates from the container that were referenced in the AML file

        This uses the pre-compiled list from AML to build a sorted list of certificates.
        Each certificate should be signed by the successor (if the AML and container is built correctly).
        This method just extracts the data from the container.
    """
    def __extractCertificatesFromContainer(self, zf: zipfile.ZipFile, chain: list[Tag]) -> list[x509.Certificate]:
        # Just read a single PEM certificate file from the container and parse the data
        def loadCertificateFromZip(filename):
            certFileData = zf.read(filename)
            return x509.load_pem_x509_certificate(certFileData)
        
        ret = []
        for cert in chain:
            self.log.debug('Processing certificate with id %s', cert['ID'])
            certLink = cert.find('ExternalInterface', RefBaseClassPath='SecurityInterfaceLib/LinkedCertificateFile')
            filename = self.__find(certLink, 'Attribute', 'refURI').Value.string
            
            filename = self.__fixPathName(filename)
            
            self.log.debug('Found path name "%s"', filename)
            fullCert = loadCertificateFromZip(filename)
            ret.append(fullCert)
        
        return ret
    
    """
        Check if the certificate chain is trusted by the user

        This checks if the user has trusted a root certificate that signed at least part of the chain.
        The method returns a new sorted list only containing the relevant certificates to be trusted and checked.
    """
    def __checkTrustAnchor(self, chain: list[x509.Certificate]) -> list[x509.Certificate]:
        if self.__args.root_cert is None:
            self.log.error('The current implementation does not use the OS trust anchors. This needs to be implemented later.')
            exit(1)
        
        # Import the trust anchor provided by the user
        with open(self.__args.root_cert[0], 'rb') as f:
            rootCertData = f.read()
        trustAnchor = x509.load_pem_x509_certificate(rootCertData)
        self.log.debug('Using trust anchor %s', trustAnchor.subject.rfc4514_string())

        newChain = []
        
        # Iterate over the list
        for c in chain:
            self.log.debug("Checking certificate %s if trusted by the trust anchor", c.subject.rfc4514_string())
            newChain.append(c)

            if c.issuer != trustAnchor.subject:
                # There is no chance the chain is finished yet. Thus continue with the next entry in the chain.
                # Note: We must not call the verify_directly_issued() method below if the certificate subjects do not match up.
                # This will otherwise trigger an Error that cannot be caught.
                continue

            try:
                # The certificate c claims to be issued by the trust anchor. Check it cryptographically.
                c.verify_directly_issued_by(trustAnchor)

                # The validation succeeded. Append the trust anchor and finish the chain calculation.
                self.log.debug('The trust could be established with the given root certificate.')
                newChain.append(trustAnchor)
                self.log.debug('The trust chain contains these certificates: %s', [x.subject.rfc4514_string() for x in newChain])
                return newChain
            except InvalidSignature:
                # The signature did not match between issuer and certificate. Potential problem with the PKI.
                self.__reportFailedTest(
                    'The certificate %s claims to be issued by the given root certificate but this cannot be verified successfully.',
                    c.subject.rfc4514_string()
                )
        
        # We reached the end of the claimed chain without finding the root certificate. No trust was established
        self.__reportFailedTest('No trust in the signature chain could be established as it is not issued by teh given root certificate.')
    
    """
        Check if the certificate chain is pairwise signed

        Each certificate must be signed by its corresponding issuer. This method checks that this is true cryptographically.
    """
    def __checkCertificateChainForValidSignatures(self, chain: list[x509.Certificate]):
        for i in range(len(chain)-1):
            try:
                self.log.debug('Checking for correct issuing of certificate %s', chain[i].subject.rfc4514_string())
                chain[i].verify_directly_issued_by(chain[i+1])
            except InvalidSignature:
                self.__reportFailedTest(
                    'The certificate %s claims to be issued by certificate %s. However the validation fails.',
                    chain[i].subject.rfc4514_string(),
                    chain[i+1].subject.rfc4514_string()
                )
            
        self.log.debug('Certificate chain was successfully verified to be pairwise signed.')

    """
        Check if any certificate in the chain has expired
    """
    def __checkCertificatesNotExpired(self, chain: list[x509.Certificate]):
        def isCertificateExpired(cert: x509.Certificate) -> bool:
            now = datetime.datetime.now()
            expired = False
            if cert.not_valid_before > now:
                self.log.warning('The lifetime of the certificate %s lies in the future', cert.subject.rfc4514_string())
                expired = True
            if cert.not_valid_after < now:
                self.log.warning('The lifetime of the certificate %s lies in the past', cert.subject.rfc4514_string())
                expired = True
            return expired
        
        for c in chain:
            self.log.debug("Checking expiry dates of certificate %s", c.subject.rfc4514_string())
            if isCertificateExpired(c):
                self.__reportFailedTest('There was an expired certificate in the chain.')
        
        self.log.debug('The certificates are all within their lifetime.')

    """
        Extract the cryptographic signature of the FMU from the AMLX container
    """
    def __getSignatureParam(self, suc: Tag):
        signatureRaw = self.__find(suc, 'Attribute', 'signature').Value.string
        signature = ''.join(signatureRaw.split('\n'))

        return signature

    """
        Check if the provided signature in the AML matches with the embedded FMU
    """
    def __validateSignature(self, amlSignature: str, leafCertificate: x509.Certificate, hash: cd.Hash):
        self.log.debug('Checking signature %s', amlSignature)

        self.log.debug('Converting signature to byte array')
        # The signature is in bytewise hexadecimal format stored in the AML
        binSig = bytes.fromhex(amlSignature)

        try:
            leafCertificate.public_key().verify(
                binSig,
                hash.hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                utils.Prehashed(hash.getFunction())
            )
            self.log.debug('The signature itself is valid')
        except InvalidSignature:
            self.__reportFailedTest('The signature could not be verified. Was the AMLX file tampered with?')

    """
        This function combines all checks for cryptographic security that need to be carried out.
    """
    def __checkCryptographicalSecurity(self, zf: zipfile.ZipFile, suc: Tag, hash: cd.Hash):
        amlChain = self.__parseCertificateChainInAML(suc)
        fullCerts = self.__extractCertificatesFromContainer(zf, amlChain)
        
        self.log.info('Checking if the certificates in the chain are to be trusted by the user.')
        fullCerts = self.__checkTrustAnchor(fullCerts)

        self.log.info('Checking if the certificate chain was correctly signed')
        self.__checkCertificateChainForValidSignatures(fullCerts)

        self.log.info('Checking if the certificates are not expired')
        self.__checkCertificatesNotExpired(fullCerts)

        self.log.info('Trust in the certificate chain has been established.')

        signature = self.__getSignatureParam(suc)
        self.__validateSignature(signature, fullCerts[0], hash)

    """
        Read the AML file in the container, run the configured checks and return the FMU embedded
    """
    def __parseRootAMLFile(self, zf: zipfile.ZipFile, filename: str) -> bytes:
        amlData = zf.read(filename)
        soup = BeautifulSoup(amlData, 'xml')
        # Get the SystemUnitClass for further handling
        suc = soup.find('SystemUnitClass', attrs={'Name': 'SafeFMU'})

        # Extract the FMU from the container
        fmuFileName = self.__getFmuFilename(suc)
        self.log.debug('Found filename for FMU %s', fmuFileName)

        fmuData = zf.read(fmuFileName)
        guessedHash = self.__guessHashFunction(suc)
        # Calculate the hash of the FMU as extracted from the container
        fmuHash = self.__calculateHashOfFile(fmuData, guessedHash)

        # First do the checks with the plain hash
        if self.__args.ignore_hash:
            self.log.warning('The hash checking has been disabled.')
        else:
            self.log.info('Checking hash of embedded FMU')
            self.__checkInternalHash(suc, fmuHash)
        
        # Second, do the checks with cryptographic involved
        if self.__args.only_hash:
            self.log.warning('The checking by cryptographical means has been disabled.')
        else:
            self.log.info('Checking by cryptographical means of the AMLX container')
            self.__checkCryptographicalSecurity(zf, suc, fmuHash)
        
        # All checks have passed or marked as failed in self.testFailed. Return the fmu as extracted.
        return fmuData

    """
        Store the FMU on the disk for use by legacy tools
    """
    def __storeFMUToFile(self, fmu: bytes):
        # Get the name of the FMU to write
        filename = self.__args.output[0]

        # Write the actual FMU
        self.log.info('Writing the FMU to the file %s', filename)
        with open(filename, 'wb') as f:
            f.write(fmu)
        
        # Calculate the hash of the FMU
        hash = cd.Hash()
        self.__calculateHashOfFile(fmu, hash)

        # Store the hash as an additional file to protect against file corruption
        with open(f'{filename}.{hash.hashName}_SUM', 'wb') as fp:
            fp.write(f'{hash.getText()} {filename}\n'.encode())
