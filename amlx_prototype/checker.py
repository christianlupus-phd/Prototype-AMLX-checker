
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.exceptions import InvalidSignature

import datetime
import os
import zipfile
import textwrap
import random
import re
import coloredlogs, logging
import sys

from pprint import pprint, pformat

from bs4 import BeautifulSoup, Tag

import amlx_prototype.cryptodata as cd

class Checker:
    def __init__(self, args) -> None:
        self.__args = args
        self.log = logging.getLogger('main.checker')
        self.testFailed = False

    def run(self):
        fmu = self.__parseAMLXContainer(self.__args.file[0])

        if self.testFailed:
            self.log.fatal('Some tests have failed. Aborting here.')
            exit(1)

        self.log.info('The FMU was successfully validated. It can be used for simulation.')

        if not self.__args.test_only:
            self.__storeFMUToFile(fmu)

    def __reportFailedTest(self, *args, **kwargs):
        self.log.fatal(*args, **kwargs)
        self.testFailed = True

        if not self.__args.force:
            exit(1)
    
    def __parseAMLXContainer(self, fileName) -> bytes:
        self.log.debug('Importing file %s', fileName)
        with zipfile.ZipFile(fileName, 'r') as zf:
            rootFileName = self.__getRootFilename(zf)
            self.log.debug('Found root AML filename "%s"', rootFileName)
            return self.__parseRootAMLFile(zf, rootFileName)
    
    def __fixPathName(self, path: str) -> str:
        return re.sub('^/*', '', path)

    def __getRootFilename(self, zf: zipfile.ZipFile):
        # relData = zf.read(os.path.join('_rels', '.rels'))
        relData = zf.read('_rels/.rels')
        soup = BeautifulSoup(relData, 'xml')
        rel = soup.find('Relationship', Type='http://schemas.automationml.org/container/relationship/RootDocument')
        target = rel['Target']
        
        return self.__fixPathName(target)

    def __find(self,parent, type, name, all=False):
        if all:
            return parent.find_all(type, attrs={'Name': name})
        else:
            return parent.find(type, attrs={'Name': name})

    def __getFmuFilename(self, suc: Tag) -> str:
        name = self.__find(
            suc.find('ExternalInterface', RefBaseClassPath="AutomationMLFMIInterfaceClassLib/FMIReference"),
            'Attribute', 'refURI'
        ).Value.string
        return self.__fixPathName(name)

    def __getHashParams(self, suc: Tag):
        hashType = self.__find(suc, 'Attribute', 'hashType').Value.string
        hashValueText = self.__find(suc, 'Attribute', 'hashValue').Value.string
        hashValue = bytes.fromhex(hashValueText)        

        hash = cd.Hash()
        hash.hashName = hashType
        hash.setHash(hashValue)

        return hash

    def __guessHashFunction(self, suc: Tag):
        tag = self.__find(suc, 'Attribute', 'hashType')
        if tag is not None and tag.Value is not None:
            hash = cd.Hash()
            hash.hashName = tag.Value.string
            return hash
        else:
            hash = cd.Hash()
            return hash

    def __calculateHashOfFile(self, data: bytes, hash: cd.Hash):
        digest = hashes.Hash(hash.getFunction())
        digest.update(data)
        raw = digest.finalize()

        hash.setHash(raw)

        self.log.debug('Calculated hash of the actual data: %s', hash.getText())

        return hash
        
    def __checkInternalHash(self, suc: Tag, hashOfFile: cd.Hash):
        hashInAML = self.__getHashParams(suc)

        textInAML = hashInAML.getText()
        textOfFile = hashOfFile.getText()

        self.log.debug('Comparing hash in AMLX container (%s) with hash of embedded FMU file (%s)', textInAML, textOfFile)
        if textInAML == textOfFile:
            self.log.debug('Hash matches')
        else:
            self.__reportFailedTest('The hash in the AMLX container does not match the hash of the embedded FMU file.')

    def __parseCertificateChainInAML(self, suc: Tag):
        
        def isRootCertificate(certTag: Tag) -> bool:
            rr = certTag.find('RoleRequirements', RefBaseRoleClassPath="SecurityRoleClassLib/RootCertificate")
            return rr is not None
        
        def getIssuingCertificateTag(certTag: Tag) -> Tag:
            issuerCertificateExternalLinkId = certTag.find('ExternalInterface', RefBaseClassPath="SecurityInterfaceLib/IssuerCertificate", recursive=False)['ID']
            internalLink = suc.find('InternalLink', RefPartnerSideB=issuerCertificateExternalLinkId)
            issuedCertificateExternalLinkId = internalLink['RefPartnerSideA']
            return suc.find(ID=issuedCertificateExternalLinkId).parent

        leaf = suc.find('RoleRequirements', RefBaseRoleClassPath='SecurityRoleClassLib/LeafCertificate').parent
        self.log.debug('Leaf certificate id: %s', leaf['ID'])
        cert = leaf
        chain = [leaf]

        while(not isRootCertificate(cert)):
            self.log.debug('Certificate %s (ID %s) is no root certificate. Continuing', cert['Name'], cert['ID'])
            cert = getIssuingCertificateTag(cert)
            chain.append(cert)
            self.log.debug("Found issuer certificate %s (ID %s)", cert['Name'], cert['ID'])
        
        self.log.debug('Found certificate chain: %s', [x['Name'] for x in chain])
        self.log.debug('Subjects" %s', [self.__find(x, 'Attribute', 'Subject').Value.string for x in chain])
        return chain

    def __extractCertificatesFromContainer(self, zf: zipfile.ZipFile,chain: list[Tag]) -> list[x509.Certificate]:
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
    
    def __checkTrustAnchor(self, chain: list[x509.Certificate]) -> list[x509.Certificate]:
        if self.__args.root_cert is None:
            self.log.error('The current implementation does not use the OS trust anchors. This needs to be implemented later.')
            exit(1)
        
        with open(self.__args.root_cert[0], 'rb') as f:
            rootCertData = f.read()
        trustAnchor = x509.load_pem_x509_certificate(rootCertData)
        self.log.debug('Using trust anchor %s', trustAnchor.subject.rfc4514_string())

        newChain = []
        
        for c in chain:
            self.log.debug("Checking certificate %s if trusted by the trust anchor", c.subject.rfc4514_string())
            newChain.append(c)

            if c.issuer != trustAnchor.subject:
                continue

            try:
                c.verify_directly_issued_by(trustAnchor)
                self.log.debug('The trust could be established with the given root certificate.')
                newChain.append(trustAnchor)
                self.log.debug('The trust chain contains these certificates: %s', [x.subject.rfc4514_string() for x in newChain])
                return newChain
            except InvalidSignature:
                self.__reportFailedTest(
                    'The certificate %s claims to be issued by the given root certificate but this cannot be verified successfully.',
                    c.subject.rfc4514_string()
                )
        
        self.__reportFailedTest('No trust in the signature chain could be established as it is not issued by teh given root certificate.')
    
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

    def __getSignatureParam(self, suc: Tag):
        signatureRaw = self.__find(suc, 'Attribute', 'signature').Value.string
        signature = ''.join(signatureRaw.split('\n'))

        return signature

    def __validateSignature(self, amlSignature: str, leafCertificate: x509.Certificate, hash: cd.Hash):
        self.log.debug('Checking signature %s', amlSignature)

        self.log.debug('Converting signature to byte array')
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

    def __parseRootAMLFile(self, zf: zipfile.ZipFile, filename: str) -> bytes:
        amlData = zf.read(filename)
        soup = BeautifulSoup(amlData, 'xml')
        suc = soup.find('SystemUnitClass', attrs={'Name': 'SafeFMU'})
        # self.log.debug(suc)

        fmuFileName = self.__getFmuFilename(suc)
        self.log.debug('Found filename for FMU %s', fmuFileName)

        fmuData = zf.read(fmuFileName)
        guessedHash = self.__guessHashFunction(suc)
        fmuHash = self.__calculateHashOfFile(fmuData, guessedHash)

        if self.__args.ignore_hash:
            self.log.warning('The hash checking has been disabled.')
        else:
            self.log.info('Checking hash of embedded FMU')
            self.__checkInternalHash(suc, fmuHash)
        
        if self.__args.only_hash:
            self.log.warning('The checking by cryptographical means has been disabled.')
        else:
            self.log.info('Checking by cryptographical means of the AMLX container')
            self.__checkCryptographicalSecurity(zf, suc, fmuHash)
        
        return fmuData

    def __storeFMUToFile(self, fmu: bytes):
        filename = self.__args.output[0]
        self.log.info('Writing the FMU to the file %s', filename)
        with open(filename, 'wb') as f:
            f.write(fmu)
        
        hash = cd.Hash()
        hasher = hash.getHasher()
        hasher.update(fmu)
        rawHash = hasher.finalize()
