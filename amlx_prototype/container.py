import datetime
import os
import zipfile
import textwrap
import random
import re
import sys
import logging
from bs4 import BeautifulSoup, Tag

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.exceptions import InvalidSignature

import amlx_prototype.cryptodata as cd

class DefaultFmuSpoofPlugin:
    def __init__(self) -> None:
        pass

    def hashData(self, hash: hashes.Hash, nominalData: bytes):
        hash.update(nominalData)
    
    def getData(self, data: bytes) -> bytes:
        return data

class AMLContainerBuilder:
    def __init__(self, boilerplatePath: str = 'boilerplate') -> None:
        self.__boilerplatePath = boilerplatePath
        self.__fmuFilename = os.path.join(boilerplatePath, 'dynamic', 'src', 'BouncingBall.fmu')
        self.__amlFileName = os.path.join(boilerplatePath, 'dynamic', 'Test.aml')

        self.__soup = None
        self.__suc = None
        self.log = logging.getLogger('main.amlx')

    def init(self):
        with open(self.__amlFileName, 'rb') as fp:
            self.__soup = BeautifulSoup(fp, 'xml')

        self.__suc = self.__soup.find('SystemUnitClass', attrs={'Name': 'SafeFMU'})

    def __findChainLink(self, name: str) -> Tag:
        return self.__suc.find('InternalElement', attrs={'Name': name})

    def __setAttribute(self, tag: Tag, name: str, newValue: str):
        self.log.debug(f'Setting attribute {name} to {newValue}')
        att = tag.find('Attribute', attrs={'Name': name})
        valueTag = self.__soup.new_tag('Value')
        att.clear()
        att.append(valueTag)
        valueTag.append(str(newValue))
        # att.Value.string = str(newValue)

    def __updateCertMetadataInXML(self, internalElement: Tag, cert: x509.Certificate):
        self.__setAttribute(internalElement, 'Serial', cert.serial_number)
        self.__setAttribute(internalElement, 'Subject', cert.subject.rfc4514_string())
        self.__setAttribute(internalElement, 'LifetimeStart', cert.not_valid_before.isoformat(' '))
        self.__setAttribute(internalElement, 'LifetimeEnd', cert.not_valid_after.isoformat(' '))

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

    def __calculateHash(self, hashPlugin: DefaultFmuSpoofPlugin = None) -> cd.Hash:
        with open(self.__fmuFilename, 'rb') as fp:
            fmuData = fp.read()
        
        hash = cd.Hash()
        hasher = hash.getHasher()
        if hashPlugin is None:
            hasher.update(fmuData)
        else:
            hashPlugin.hashData(hasher, fmuData)
        
        hash.setHash(hasher.finalize())
        self.log.debug('Obtained hash for FMU is %s', hash.getText())
        return hash

    def __updateHashInDT(self, hash: cd.Hash):
        self.__setAttribute(self.__suc, 'hashType', hash.hashName)
        self.__setAttribute(self.__suc, 'hashValue', hash.getText())

    def __updateSignatureInDT(self, crypto: cd.LocalCryptographicData, hash: cd.Hash):
        sigBytes = crypto.leafCert.key.sign(
            hash.hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(hash.getFunction())
        )
        sigLine = ''.join(['{0:02x}'.format(x) for x in sigBytes])
        sig = '\n'.join(textwrap.wrap(sigLine, 32))

        self.__setAttribute(self.__suc, 'signature', sig)

    def updateDTData(self, crypto: cd.LocalCryptographicData, callbackPlugin: DefaultFmuSpoofPlugin = None):
        nominalHash = self.__calculateHash(DefaultFmuSpoofPlugin())
        
        if callbackPlugin is None:
            hash = nominalHash
        else:
            hash = self.__calculateHash(callbackPlugin)
        
        self.__updateCertificateData(crypto)
        self.__updateHashInDT(hash)
        self.__updateSignatureInDT(crypto, nominalHash)

        self.__soup.smooth()

    def createContainer(self, containerName: str, callbackPlugin: DefaultFmuSpoofPlugin):
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

        def addCertificates(zf):
            zf.write(os.path.join(self.__boilerplatePath, 'generated', 'ca', 'cert.pem'), os.path.join('ca', 'cert.pem'))
            zf.write(os.path.join(self.__boilerplatePath, 'generated', 'im', 'cert.pem'), os.path.join('im', 'cert.pem'))
            zf.write(os.path.join(self.__boilerplatePath, 'generated', 'vendor', 'cert.pem'), os.path.join('vendor', 'cert.pem'))
            zf.write(os.path.join(self.__boilerplatePath, 'generated', 'fmu', 'cert.pem'), os.path.join('fmu', 'cert.pem'))

        def addAMLFile(zf):
            zf.writestr('Test.aml', str(self.__soup).encode('utf-8-sig'))
        
        def addFMUFile(zf, callbackPlugin: DefaultFmuSpoofPlugin):
            with open(self.__fmuFilename, 'rb') as fp:
                fmuNominal = fp.read()
            
            fmu = callbackPlugin.getData(fmuNominal)
            self.log.debug('Using an FMU file of length %d (nominal length is %d)', len(fmu), len(fmuNominal))
            if fmu == fmuNominal:
                self.log.debug('The FMU data was not modified')
            else:
                self.log.debug('The data has been changed compared to the nominal FMU in the boilerplate folder')
            
            zf.writestr(os.path.join('src', 'BouncingBall.fmu'), fmu)

        with zipfile.ZipFile(containerName, 'w', zipfile.ZIP_DEFLATED) as zf:
            addStaticContent(zf)
            addCertificates(zf)
            addAMLFile(zf)
            addFMUFile(zf, callbackPlugin)
    
    def writePureAMLFile(self, amlFileName: str):
        with open(amlFileName, 'wb') as fp:
            fp.write(self.__soup.prettify().encode('utf-8-sig'))


        # os.makedirs(os.path.join('data', 'tmp'), exist_ok=True)
