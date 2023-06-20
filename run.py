#!/bin/env python

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

from bs4 import BeautifulSoup

import amlx_prototype

verbosityLevel = {
    0: logging.WARN,
    1: logging.INFO,
}
coloredlogs.install(level=verbosityLevel.get(amlx_prototype.cli.args.verbose, logging.DEBUG), stream=sys.stdout)
logging.basicConfig(level=logging.NOTSET, stream=sys.stdout)
logger = logging.getLogger('main')

logger.debug("Found CLI parameters: %s", amlx_prototype.cli.args)

workerMap = {
    'bootstrap': amlx_prototype.bootstrapper.Bootstrapper,
    'sign': None,
    'check': None,
}

worker = workerMap[amlx_prototype.cli.args.cmd](amlx_prototype.cli.args)
worker.run()

exit(0)


# print(log.getEffectiveLevel(), log.level)

# def runBootstrap():

    

    # def loadAMLTemplate():
    #     with open(os.path.join('boilerplate', 'dynamic', 'Test.aml'), 'rb') as fp:
    #         return BeautifulSoup(fp, 'xml')

    # soup = loadAMLTemplate()
    # suc = soup.find('SystemUnitClass', attrs={'Name': 'SafeFMU'})

    # def findChainLink(name):
    #     return suc.find('InternalElement', attrs={'Name': name})

    # def setAttribute(tag, name, newValue):
    #     # print(f'Setting attribute {name} to {newValue}')
    #     att = tag.find('Attribute', attrs={'Name': name})
    #     valueTag = soup.new_tag('Value')
    #     att.clear()
    #     att.append(valueTag)
    #     valueTag.append(str(newValue))
    #     # att.Value.string = str(newValue)

    # def updateCertMetadataInXML(ie, cert):
    #     setAttribute(ie, 'Serial', cert.serial_number)
    #     setAttribute(ie, 'Subject', cert.subject.rfc4514_string())
    #     setAttribute(ie, 'LifetimeStart', cert.not_valid_before.isoformat(' '))
    #     setAttribute(ie, 'LifetimeEnd', cert.not_valid_after.isoformat(' '))

    # rootCert = findChainLink('RootCertificate')
    # # print()
    # # print(rootCert.prettify())

    # updateCertMetadataInXML(rootCert, crypto['ca']['cert'])

    # # print()
    # # print(rootCert.prettify())

    # updateCertMetadataInXML(findChainLink('ChainLink1'), crypto['chain'][1]['cert'])
    # updateCertMetadataInXML(findChainLink('ChainLink2'), crypto['chain'][2]['cert'])
    # updateCertMetadataInXML(findChainLink('ChainLink3'), crypto['leaf']['cert'])

    # def writeAMLXFile(filename, tamperFMU, tamperHash):
        
    #     fmuFilename = os.path.join('boilerplate', 'dynamic', 'src', 'BouncingBall.fmu')

    #     def calculateHash(finisher = None):
    #         def hashBuffer(fp, finisher = None):
    #             # hashName = 'SHA384'
    #             hashName = 'SHA256'
    #             hashFunction = getattr(hashes, hashName)()
    #             hasher = hashes.Hash(hashFunction)
                
    #             size = 1024
    #             buf = fp.read(size)
    #             while len(buf) > 0:
    #                 hasher.update(buf)
    #                 buf = fp.read(size)
                
    #             if finisher is not None:
    #                 finisher(hasher)

    #             hash = hasher.finalize()
    #             # print(len(hash))
    #             # print(hash)

    #             return (hash, hashName, hashFunction)


    #         with open(fmuFilename, 'rb') as fp:
    #             hash, hashName, hashFunction = hashBuffer(fp, finisher)

    #         hashText = ''.join(['{0:02x}'.format(x) for x in hash])
    #         # print(hashText)
            
    #         return (hash, hashFunction, hashName, hashText)

    #     def setHashInDT(hashName, hashText):
    #         setAttribute(suc, 'hashType', hashName)
    #         setAttribute(suc, 'hashValue', hashText)

    #     tamperAppend = random.randbytes(10)

    #     def finisherChangeFile(hasher):
    #         if tamperFMU:
    #             hasher.update(tamperAppend)

    #     hashNominal, hashFunctionNominal, hashName, hashTextNominal = calculateHash()
    #     # hashNominal, hashFunctionNominal = updateHashInDT()

    #     def calculateSignature(hash, hashFunction):
    #         sigBytes = crypto['leaf']['key'].sign(hash,
    #             padding.PSS(
    #                 mgf=padding.MGF1(hashes.SHA256()),
    #                 salt_length=padding.PSS.MAX_LENGTH
    #             ),
    #             utils.Prehashed(hashFunction)
    #         )
    #         return ''.join(['{0:02x}'.format(x) for x in sigBytes])

    #     sigLine = calculateSignature(hashNominal, hashFunctionNominal)
    #     sig = '\n'.join(textwrap.wrap(sigLine, 64))
    #     # Set the signature to the nominal signature
    #     setAttribute(suc, 'signature', sig)

    #     if tamperHash:
    #         hash, hashFunction, hashName, hashText = calculateHash(finisherChangeFile)
    #     else:
    #         hash = hashNominal
    #         hashFunction = hashFunctionNominal
    #         hashText = hashTextNominal

    #     setHashInDT(hashName, hashText)

    #     soup.smooth()

    #     # print()
    #     # print()
    #     # print(suc.prettify())
    #     # print(soup.prettify())

    #     def addStaticContent(zf):
    #         topDir = os.path.join('boilerplate', 'static')
    #         for root, dirs, files in os.walk(topDir):
    #             relDir = os.path.relpath(root, topDir)
    #             # for d in dirs:
    #                 # zf.mkdir(os.path.join(relDir, d))
    #             for f in files:
    #                 zf.write(
    #                     os.path.join(root, f),
    #                     os.path.join(relDir, f)
    #                 )

    #     def addCertificates(zf):
    #         zf.write(os.path.join('boilerplate', 'generated', 'ca', 'cert.pem'), os.path.join('ca', 'cert.pem'))
    #         zf.write(os.path.join('boilerplate', 'generated', 'im', 'cert.pem'), os.path.join('im', 'cert.pem'))
    #         zf.write(os.path.join('boilerplate', 'generated', 'vendor', 'cert.pem'), os.path.join('vendor', 'cert.pem'))
    #         zf.write(os.path.join('boilerplate', 'generated', 'fmu', 'cert.pem'), os.path.join('fmu', 'cert.pem'))

    #     def addAMLFile(zf):
    #         zf.writestr('Test.aml', str(soup).encode('utf-8-sig'))
        
    #     def addFMUFile(zf):
    #         with open(fmuFilename, 'rb') as fp:
    #             fmu = fp.read()
            
    #         if tamperFMU:
    #             fmu = fmu + tamperAppend
            
    #         zf.writestr(os.path.join('src', 'BouncingBall.fmu'), fmu)

    #     os.makedirs(os.path.join('data', 'tmp'), exist_ok=True)
    #     with open(os.path.join('data', 'tmp', 'Root.aml'), 'wb') as fp:
    #         fp.write(soup.prettify().encode('utf-8-sig'))

    #     with zipfile.ZipFile(filename, 'w', zipfile.ZIP_DEFLATED) as zf:
    #         addStaticContent(zf)
    #         addCertificates(zf)
    #         addAMLFile(zf)
    #         addFMUFile(zf)

    # os.makedirs('fmus', exist_ok=True)
    # writeAMLXFile(os.path.join('fmus', 'nominal_fmu.amlx'), False, False)
    # writeAMLXFile(os.path.join('fmus', 'broken_fmu.amlx'), True, False)
    # writeAMLXFile(os.path.join('fmus', 'tampered_fmu.amlx'), True, True)

def runCheck():
    with zipfile.ZipFile(args.file[0], 'r') as zf:
        
        def checkAMLXFile():
            files = zf.namelist()
            reAml = re.compile('.*\.aml$')
            amlFiles = [x for x in files if reAml.match(x)]
            if len(amlFiles) != 1:
                print('The number of found AML files in the container is not 1. This is not supported currently.')
                exit(1)

            reFMU = re.compile('.*\.fmu$')
            fmuFiles = [x for x in files if reFMU.match(x)]
            if len(fmuFiles) != 1:
                print('There must be exactly one FMU in the container. Everything else is not supported.')
                exit(1)
            
            return (amlFiles[0], fmuFiles[0])
        
        def find(parent, type, name, all=False):
            if all:
                return parent.find_all(type, attrs={'Name': name})
            else:
                return parent.find(type, attrs={'Name': name})
        
        def getHashParams(suc):
            hashType = find(suc, 'Attribute', 'hashType').Value.string
            hashValue = find(suc, 'Attribute', 'hashValue').Value.string
            signatureRaw = find(suc, 'Attribute', 'signature').Value.string
            signature = ''.join(signatureRaw.split('\n'))
            return (hashType, hashValue, signature)
        
        def calculateHashOfFmu(hashType, fmu):
            hashFunction = getattr(hashes, hashType)()
            digest = hashes.Hash(hashFunction)
            digest.update(fmu)
            raw = digest.finalize()
            hexEntries = ['{0:02x}'.format(x) for x in raw]
            hash = ''.join(hexEntries)
            log.debug('Calculated Hash of the actual FMU: %s', hash)
            return (hash, raw, hashFunction)
        
        def parseCertificateChain(suc):
            log.info('Extracting the certificate information from AML')

            log.debug('Obtaining certificate information')
            leaf = suc.find('RoleRequirements', RefBaseRoleClassPath='SecurityRoleClassLib/LeafCertificate').parent
            root = suc.find('RoleRequirements', RefBaseRoleClassPath='SecurityRoleClassLib/RootCertificate').parent
            chainLinks = map(lambda x: x.parent, suc.find_all('RoleRequirements', RefBaseRoleClassPath='SecurityRoleClassLib/ChainLink'))

            certsById = {
                leaf['ID']: leaf,
                root['ID']: root,
            }
            for l in chainLinks:
                certsById[l['ID']] = l
            log.debug("Found %d certificates in the AMLX.", len(certsById))

            log.debug('Extracting internal link information')
            certsByIssuerLinkIds = {}
            certsByIssuedLinkIds = {}

            def getLinkInterface(cert, name):
                return cert.find('ExternalInterface', attrs={'Name': name}, recusive=False)

            def findInterfaces(cert, name, struct):
                interface = getLinkInterface(cert, name)
                if interface is not None:
                    struct[interface['ID']] = cert

            for id in certsById:
                findInterfaces(certsById[id], 'IssuerCertificate', certsByIssuerLinkIds)
                findInterfaces(certsById[id], 'IssuedCertificate', certsByIssuedLinkIds)

            log.debug('Issuer certificates link ids: %s', list(certsByIssuerLinkIds.keys()))
            log.debug('Issued certificates link ids: %s', list(certsByIssuedLinkIds.keys()))

            log.debug('Getting the certificate links')
            links = suc.find_all('InternalLink')
            log.debug('Found %d internal links totally.', len(links))
            log.debug(links)
            links = [x for x in links if x['RefPartnerSideA'] in certsByIssuedLinkIds and x['RefPartnerSideB'] in certsByIssuerLinkIds]
            log.debug('Remaining %d links after filtering', len(links))

            linksByIssuerId = {}
            for l in links:
                linksByIssuerId[l['RefPartnerSideB']] = l

            log.debug('Building certificate chain as list')
            chain = [leaf]
            currentCert = leaf
            while currentCert != root:
                issuerInterface = getLinkInterface(currentCert, 'IssuerCertificate')
                link = linksByIssuerId[issuerInterface['ID']]
                nextCert = certsByIssuedLinkIds[link['RefPartnerSideA']]
                chain.append(nextCert)
                currentCert = nextCert
            log.debug('Found certificate chain: %s', [x['Name'] for x in chain])

            return (chain)

        def getRealCertificateChain(chain, zf):
            def loadCertificateFromZip(filename):
                certFileData = zf.read(filename)
                return x509.load_pem_x509_certificate(certFileData)
            
            ret = []
            for link in chain:
                log.debug('Processing link with id %s', link['ID'])
                certLink = link.find('ExternalInterface', RefBaseClassPath='SecurityInterfaceLib/LinkedCertificateFile')
                filename = certLink.find('Attribute', attrs={'Name': 'refURI'}).Value.string
                
                # Fix the URL by dropping leading /
                filename = re.sub('^/*', '', filename)
                
                log.debug('Found path name "%s"', filename)
                fullCert = loadCertificateFromZip(filename)
                ret.append(fullCert)
            
            return ret

        def checkSignature(cert, hashRaw, hashFunction, sig):
            log.debug('Checking signature %s', sig)

            log.debug('Converting signature to byte array')
            bytesStr = textwrap.wrap(sig, 2)
            binSig = [int(x,16) for x in bytesStr]

            try:
                cert.public_key().verify(
                    binSig,
                    hashRaw,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    utils.Prehashed(hashFunction)
                )
                log.debug('The signature itself is valid')
            except InvalidSignature:
                log.error('The signature could not be verified. Was the AMLX file tampered?')
                log.warning('The simulation should not be called for security reasons.')
                exit(1)

        def certificateDatesValid(cert):
            now = datetime.datetime.now()
            if cert.not_valid_before > now:
                log.error('The lifetime of the certificate %s lies in the future', cert.subject.rfc4514_string())
                return False
            if cert.not_valid_after < now:
                log.error('The lifetime of the certificate %s lies in the past', cert.subject.rfc4514_string())
                return False
            return True
        
        def checkCertificateChainCorrectlySigned(chain):
            log.info('Checking if the chain in question is a real chain and is pairwise signed.')
            for i in range(len(chain)-1):
                try:
                    chain[i].verify_directly_issued_by(chain[i+1])
                except InvalidSignature:
                    return False
                
            return True
        
        def checkCertificateDates(chain):
            log.info('Checking the lifetime dates of the certificates')
            for c in chain:
                if not certificateDatesValid(c):
                    return False
            return True
        
        def checkTrustAnchor(chain):
            if args.root_cert is None:
                log.error('The current implementation does not use the OS trust anchors. This needs to be implemented later.')
                exit(1)
            
            with open(args.root_cert[0], 'rb') as f:
                rootCertData = f.read()
            trustAnchor = x509.load_pem_x509_certificate(rootCertData)
            for c in chain:
                if c.issuer != trustAnchor.subject:
                    continue

                try:
                    c.verify_directly_issued_by(trustAnchor)
                    return True
                except InvalidSignature:
                    pass
            
            return False

        amlFileName, fmuFileName = checkAMLXFile()
        aml = zf.read(amlFileName)
        fmu = zf.read(fmuFileName)

        soup = BeautifulSoup(aml, 'xml')
        suc = soup.find('SystemUnitClass', attrs={'Name': 'SafeFMU'})

        log.info('Checking hash of FMU')
        hashType, hashValue, signature = getHashParams(suc)
        log.debug('FMU should have hash %s using hash %s', hashValue, hashType)
        realHash, realHashRaw, hashFunction = calculateHashOfFmu(hashType, fmu)
        # print(hashValue, realHash)
        if hashValue != realHash:
            log.error('The hash of the FMU and the stored hash do not match. The FMU might be broken.')
            exit(1)
        else:
            log.info('The Hash matches')

        log.info('Extracting certificates from the AMLX file')
        amlChain = parseCertificateChain(suc)
        certChain = getRealCertificateChain(amlChain, zf)

        log.info('Checking if the chain is based on a common trust anchor')
        if not checkTrustAnchor(certChain):
            log.error('The certificate chain was not trusted by the given root CA (parameter -r).')
            exit(1)
        
        log.info('Checking certificate chain')
        if not checkCertificateChainCorrectlySigned(certChain):
            log.error('The certificate chain as declared in AMLX is not correctly built')
            exit(1)
        if not checkCertificateDates(certChain):
            log.error('The certificate is expired.')
            exit(1)
        
        log.info('Checking the signature of the certificate')
        checkSignature(certChain[0], realHashRaw, hashFunction, signature)

        log.warning('The trust was technically established. The implementation of custom policies is not yet done.')

        log.info('The FMU was successfully checked and seems valid.')

        if args.output is not None:
            log.info('Writing the FMU to the file %s', args.output[0])
            with open(args.output[0], 'wb') as f:
                f.write(fmu)
            with open(f'{args.output[0]}.{hashType}_SUM', 'w') as f:
                dir, filename = os.path.split(args.output[0])
                # log.debug('Filename "%s" was split into "%s" and "%s"', args.output[0], dir, filename)
                f.write(f'{hashValue} {filename}')

            log.info('File has been written.')
        else:
            log.warning('There is no simulation core implemented. This program is just a proof of concept.')
            print('Now the simulation would be run but in the prototype no implementation is made.')

callMap = {
    'bootstrap': runBootstrap,
    'check': runCheck,
}

callMap[args.cmd]()
