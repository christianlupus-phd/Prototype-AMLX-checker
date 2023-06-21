import os
import zipfile
import textwrap
import logging
from bs4 import BeautifulSoup, Tag

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils

import amlx_prototype.cryptodata as cd

"""
    This class provides a way to tamper with the FMU and the hash of it in the AMLX file.

    It can be used as a parent class to implement various ways to modify the FMU.
    The implementation here will not change anything but represents the nominal behavior.
"""
class DefaultFmuSpoofPlugin:
    def __init__(self) -> None:
        pass

    """
        Hash the data in question using the provided hashing method
        This method should simply update the hasher and not finalize it (see default implementation).
    """
    def hashData(self, hash: hashes.Hash, nominalData: bytes):
        hash.update(nominalData)
    
    """
        Get the FMU data to be written to the AMLX file.
        This mapping is used just before writing the FMU to the AMLX file.
    """
    def getData(self, data: bytes) -> bytes:
        return data

"""
    This class provides a way to create a new AMLX container.
"""
class AMLContainerBuilder:
    
    """
        Prepare a new container builder

        The parameter boilerplatePath allows to read the boilerplate data from arbitrary folders.
        If the parameter fmuFilename is given, the FMU is read from there instead of the boilerplate.
    """
    def __init__(self, boilerplatePath: str = 'boilerplate', fmuFilename: str = None) -> None:
        self.__boilerplatePath = boilerplatePath

        if fmuFilename is None:
            self.__fmuFilename = os.path.join(boilerplatePath, 'dynamic', 'src', 'BouncingBall.fmu')
        else:
            self.__fmuFilename = fmuFilename
        
        self.__amlFileName = os.path.join(boilerplatePath, 'dynamic', 'Test.aml')

        self.__soup = None
        self.__suc = None
        self.log = logging.getLogger('main.amlx')

    """
        Read in the AML file to populate the internal structures in memory
    """
    def init(self):
        with open(self.__amlFileName, 'rb') as fp:
            self.__soup = BeautifulSoup(fp, 'xml')

        self.__suc = self.__soup.find('SystemUnitClass', attrs={'Name': 'SafeFMU'})

    """
        Search in the AML (XML) file for an internal element with given name
    """
    def __findChainLink(self, name: str) -> Tag:
        return self.__suc.find('InternalElement', attrs={'Name': name})

    """
        Update a single attribute in AML with a value
    """
    def __setAttribute(self, tag: Tag, name: str, newValue: str):
        self.log.debug(f'Setting attribute {name} to {newValue}')
        
        # Get the attribute tag in the XML and remove any children
        att = tag.find('Attribute', attrs={'Name': name})
        att.clear()

        # Create a new tag with the value and attach it to the attribute XML tag
        valueTag = self.__soup.new_tag('Value')
        att.append(valueTag)
        valueTag.append(str(newValue))

    """
        Set the metadata of one certificate in the AML structure
    """
    def __updateCertMetadataInXML(self, internalElement: Tag, cert: x509.Certificate):
        self.__setAttribute(internalElement, 'Serial', cert.serial_number)
        self.__setAttribute(internalElement, 'Subject', cert.subject.rfc4514_string())
        self.__setAttribute(internalElement, 'LifetimeStart', cert.not_valid_before.isoformat(' '))
        self.__setAttribute(internalElement, 'LifetimeEnd', cert.not_valid_after.isoformat(' '))

    """
        Update the AML data to contain the meta information of all certificates in the chain
    """
    def __updateCertificateData(self, crypto: cd.LocalCryptographicData):
        rootCert = self.__findChainLink('RootCertificate')
        # print()
        # print(rootCert.prettify())

        self.__updateCertMetadataInXML(rootCert, crypto.rootCert)

        # print()
        # print(rootCert.prettify())

        self.__updateCertMetadataInXML(self.__findChainLink('ChainLink1'), crypto.chain[1])
        self.__updateCertMetadataInXML(self.__findChainLink('ChainLink2'), crypto.chain[2])
        self.__updateCertMetadataInXML(self.__findChainLink('ChainLink3'), crypto.leafCert.cert)

    """
        Calculate the hash of a FMU with a spoof plugin included
    """
    def __calculateHash(self, spoofPlugin: DefaultFmuSpoofPlugin) -> cd.Hash:
        with open(self.__fmuFilename, 'rb') as fp:
            fmuData = fp.read()
        
        hash = cd.Hash()
        hasher = hash.getHasher()

        # Let the plugin hash the FMU, normally just calling hasher.update() on the fmu data.
        spoofPlugin.hashData(hasher, fmuData)
        
        hash.setHash(hasher.finalize())
        self.log.debug('Obtained hash for FMU is %s', hash.getText())
        return hash

    """
        Set the hash as calculated in the AML memory representation
    """
    def __updateHashInDT(self, hash: cd.Hash):
        self.__setAttribute(self.__suc, 'hashType', hash.hashName)
        self.__setAttribute(self.__suc, 'hashValue', hash.getText())

    """
        Calculate the signature of the nominal FMU and put it in the AML structure
    """
    def __updateSignatureInDT(self, crypto: cd.LocalCryptographicData, hash: cd.Hash):
        # Use the already calculated hash to sign the data
        sigBytes = crypto.leafCert.key.sign(
            hash.hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(hash.getFunction())
        )

        # The signature is in binary form by default, this just makes a hexadecimal representation and breaks every 32 chars
        sigLine = ''.join(['{0:02x}'.format(x) for x in sigBytes])
        sig = '\n'.join(textwrap.wrap(sigLine, 32))

        # Update the AML structure with the signature text
        self.__setAttribute(self.__suc, 'signature', sig)

    """
        This method updates all data in the internal representation to comply with the current FMU

        This can only be called after calling the init() method.
        After this method, the AMLX container can be exported by createContainer() or an intermediate AML file using writePureAMLFile().
    """
    def updateDTData(self, crypto: cd.LocalCryptographicData, callbackPlugin: DefaultFmuSpoofPlugin = None):
        # Calculate the hash of the real FMU data for the signature.
        # This is the hash that was calculated on the vendor's machine.
        nominalHash = self.__calculateHash(DefaultFmuSpoofPlugin())
        
        # If another plugin should be used to calculate the hash as stored in the FMU, calculate the spoofed hash as well.
        if callbackPlugin is None:
            hash = nominalHash
        else:
            hash = self.__calculateHash(callbackPlugin)
        
        # Update the AML structures from the crypto data
        self.__updateCertificateData(crypto)
        # The hash to be saved in AML should be the spoofed one
        self.__updateHashInDT(hash)
        # The certificate uses always the original hash
        self.__updateSignatureInDT(crypto, nominalHash)

        # Clean up a bit the XML file
        self.__soup.smooth()

    """
        Store a AMLX file on the disk
    """
    def createContainer(self, containerName: str, pkiPath: str, callbackPlugin: DefaultFmuSpoofPlugin|None = None):
        """
            Store all content in the static folder directly in the AMLX file.
            These files will be considered static content.
        """
        def addStaticContent(zf):
            topDir = os.path.join(self.__boilerplatePath, 'static')
            for root, dirs, files in os.walk(topDir):
                relDir = os.path.relpath(root, topDir)
                # for d in dirs:
                    # zf.mkdir(os.path.join(relDir, d))
                for f in files:
                    zf.write(
                        os.path.join(root, f),
                        os.path.join(relDir, f)
                    )

        """
            Add the certificates to the AMLX container.

            The certificates are loaded from the pre-generated PKI folder
        """
        def addCertificates(zf, pkiPath):
            zf.write(os.path.join(pkiPath, 'ca', 'cert.pem'), os.path.join('ca', 'cert.pem'))
            zf.write(os.path.join(pkiPath, 'im', 'cert.pem'), os.path.join('im', 'cert.pem'))
            zf.write(os.path.join(pkiPath, 'vendor', 'cert.pem'), os.path.join('vendor', 'cert.pem'))
            zf.write(os.path.join(pkiPath, 'fmu', 'cert.pem'), os.path.join('fmu', 'cert.pem'))

        """
            Add the AML file to the container from the internal (in-memory) data structures
        """
        def addAMLFile(zf):
            zf.writestr('Test.aml', str(self.__soup).encode('utf-8-sig'))
        
        """
            Add the actual FMU file to the container applying the plugin filtering
        """
        def addFMUFile(zf, callbackPlugin: DefaultFmuSpoofPlugin):
            with open(self.__fmuFilename, 'rb') as fp:
                fmuNominal = fp.read()
            
            # Apply the spoof filter
            fmu = callbackPlugin.getData(fmuNominal)

            self.log.debug('Using an FMU file of length %d (nominal length is %d)', len(fmu), len(fmuNominal))
            if fmu == fmuNominal:
                self.log.debug('The FMU data was not modified')
            else:
                self.log.debug('The data has been changed compared to the nominal FMU in the boilerplate folder')
            
            zf.writestr(os.path.join('src', 'BouncingBall.fmu'), fmu)

        if callbackPlugin is None:
            callbackPlugin = DefaultFmuSpoofPlugin()

        with zipfile.ZipFile(containerName, 'w', zipfile.ZIP_DEFLATED) as zf:
            addStaticContent(zf)
            addCertificates(zf, pkiPath)
            addAMLFile(zf)
            addFMUFile(zf, callbackPlugin)
    
    """
        Output the internal data structures in form of a AML file

        This allows simpler inspection and debugging
    """
    def writePureAMLFile(self, amlFileName: str):
        with open(amlFileName, 'wb') as fp:
            fp.write(self.__soup.prettify().encode('utf-8-sig'))


        # os.makedirs(os.path.join('data', 'tmp'), exist_ok=True)
