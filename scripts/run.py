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
import argparse
import re
import coloredlogs, logging
import sys

from pprint import pprint, pformat

from bs4 import BeautifulSoup


parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers(dest='cmd', required=True)

bootstrapParser = subparsers.add_parser('bootstrap')

checkerParser = subparsers.add_parser('check')
checkerParser.add_argument('file', nargs=1)
checkerParser.add_argument('-v', '--verbose', action='count', default=0)

args = parser.parse_args()
# print(args)

verbosityLevel = {
    0: logging.WARN,
    1: logging.INFO,
}
coloredlogs.install(level=verbosityLevel.get(args.verbose, logging.DEBUG))
logging.basicConfig(level=logging.NOTSET, stream=sys.stdout)
log = logging.getLogger('Main')
# print(log.getEffectiveLevel(), log.level)

def runBootstrap():

    def prepareCryptography():

        oneDay = datetime.timedelta(1,0,0)

        def generatePrivateKey():
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )

            return {
                'key': key,
                'bytes': key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            }

        def createCSR(subj, key):
            attribs = ','.join([f'{k}={v}' for k,v in subj.items()])

            # if 'C' in subj:
            #     attribs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, ))
            csr = x509.CertificateSigningRequestBuilder().subject_name(
                x509.Name.from_rfc4514_string(attribs)
                ).sign(key, hashes.SHA256())
            return csr

        def signCSR(csr, caKey, caCert, days):
            builder = x509.CertificateBuilder()
            today = datetime.datetime.today()
            builder = builder.subject_name(csr.subject).issuer_name(caCert.subject) \
                .not_valid_before(today) \
                .not_valid_after(today + (oneDay * days)) \
                .public_key(csr.public_key()) \
                .serial_number(x509.random_serial_number())
            return builder.sign(private_key=caKey, algorithm=hashes.SHA256())

        def generateCA():
            key = generatePrivateKey()
            key = key['key']
            csr = createCSR({
                'C': 'DE',
                'ST': 'Baden-Wuerttemberg',
                'CN': 'FMU-Tester'
            }, key)
            cert = signCSR(csr, key, csr, 3650)
            return {
                'key': key,
                'cert': cert
            }

        def createCertChainLink(subject, issuer, days):
            key = generatePrivateKey()
            key = key['key']
            csr = createCSR(subject, key)
            cert = signCSR(csr, issuer['key'], issuer['cert'], days)
            return {
                'key': key,
                'cert': cert
            }

        def strCertificateChainLink(link, printKey=False):
            certOut = link['cert'].public_bytes(serialization.Encoding.PEM).decode()
            out = certOut
            if printKey:
                keyOut = link['key'].private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode()
                out = f'{out}\n{keyOut}'
            return out

        def isCertExisting(name):
            base = os.path.join('data', name)
            if not os.path.exists(base):
                return False
            
            if not os.path.exists(os.path.join(base, 'cert.pem')):
                return False
            if not os.path.exists(os.path.join(base, 'key.pem')):
                return False
            
            return True

        def loadCert(name):
            base = os.path.join('data', name)
            def loadData(file):
                with open(os.path.join(base, file), 'r') as f:
                    return f.read().encode()
            
            keyData = loadData('key.pem')
            certData = loadData('cert.pem')
            return {
                'key': serialization.load_pem_private_key(keyData, password=None),
                'cert': x509.load_pem_x509_certificate(certData)
            }

        def storeCert(name, link):
            base = os.path.join('data', name)
            os.makedirs(base, exist_ok=True)
            def storeData(file, d):
                with open(os.path.join(base, file), 'w') as f:
                    f.write(d.decode())
            
            storeData('key.pem', link['key'].private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
            storeData('cert.pem', link['cert'].public_bytes(
                encoding=serialization.Encoding.PEM
            ))

        def ensureCertLinkExists(name, subj, issuer, days):
            if isCertExisting(name):
                print(f'Loading certificate chain link "{name}" from disk')
                return loadCert(name)
            else:
                print(f'Creating certificate "{name}"')
                link = createCertChainLink(subj, issuer, days)

                print('Storing created certificate chain link to disk')
                storeCert(name, link)
                
                return link

        # Check for root certificate
        if isCertExisting('ca'):
            print('Loading CA from disk')
            ca = loadCert('ca')
        else:
            print('Generating new CA')
            ca = generateCA()

            print('Storing CA to disk')
            storeCert('ca', ca)

        # print(strCertificateChainLink(ca))

        im = ensureCertLinkExists('im', {
            'C': 'DE',
            'ST': 'Baden-Wuerttemberg',
            'CN': 'FMU-Tester'
        }, ca, 3650)
        # print(strCertificateChainLink(im))

        vendor = ensureCertLinkExists('vendor', {
            'C': 'DE',
            'ST': 'Baden-Wuerttemberg',
            'O': 'EKS Intec',
            'CN': 'Research'
        }, im, 500)

        fmuCert = ensureCertLinkExists('fmu', {
            'C': 'DE',
            'ST': 'Baden-Wuerttemberg',
            'O': 'EKS Intec',
            'OU': 'Research',
            'CN': 'BouncingBall'
        }, vendor, 150)

        return {
            'ca': ca,
            'chain': [ca, im, vendor],
            'leaf': fmuCert
        }

    def mapCrypto(crypto):
        del crypto['ca']['key']
        for i in range(len(crypto['chain'])):
            crypto['chain'][i].pop('key', None)
        return crypto

    crypto = mapCrypto(prepareCryptography())
    # pprint(crypto)



    def loadAMLTemplate():
        with open(os.path.join('boilerplate', 'dynamic', 'Test.aml'), 'rb') as fp:
            return BeautifulSoup(fp, 'xml')

    soup = loadAMLTemplate()
    suc = soup.find('SystemUnitClass', attrs={'Name': 'SafeFMU'})

    def findChainLink(name):
        return suc.find('InternalElement', attrs={'Name': name})

    def setAttribute(tag, name, newValue):
        # print(f'Setting attribute {name} to {newValue}')
        att = tag.find('Attribute', attrs={'Name': name})
        valueTag = soup.new_tag('Value')
        att.clear()
        att.append(valueTag)
        valueTag.append(str(newValue))
        # att.Value.string = str(newValue)

    def updateCertMetadataInXML(ie, cert):
        setAttribute(ie, 'Serial', cert.serial_number)
        setAttribute(ie, 'Subject', cert.subject.rfc4514_string())
        setAttribute(ie, 'LifetimeStart', cert.not_valid_before.isoformat(' '))
        setAttribute(ie, 'LifetimeEnd', cert.not_valid_after.isoformat(' '))

    rootCert = findChainLink('RootCertificate')
    # print()
    # print(rootCert.prettify())

    updateCertMetadataInXML(rootCert, crypto['ca']['cert'])

    # print()
    # print(rootCert.prettify())

    updateCertMetadataInXML(findChainLink('ChainLink1'), crypto['chain'][1]['cert'])
    updateCertMetadataInXML(findChainLink('ChainLink2'), crypto['chain'][2]['cert'])
    updateCertMetadataInXML(findChainLink('ChainLink3'), crypto['leaf']['cert'])

    def writeAMLXFile(filename, tamperFMU, tamperHash):
        
        fmuFilename = os.path.join('boilerplate', 'dynamic', 'src', 'BouncingBall.fmu')

        def calculateHash(finisher = None):
            def hashBuffer(fp, finisher = None):
                # hashName = 'SHA384'
                hashName = 'SHA256'
                hashFunction = getattr(hashes, hashName)()
                hasher = hashes.Hash(hashFunction)
                
                size = 1024
                buf = fp.read(size)
                while len(buf) > 0:
                    hasher.update(buf)
                    buf = fp.read(size)
                
                if finisher is not None:
                    finisher(hasher)

                hash = hasher.finalize()
                # print(len(hash))
                # print(hash)

                return (hash, hashName, hashFunction)


            with open(fmuFilename, 'rb') as fp:
                hash, hashName, hashFunction = hashBuffer(fp, finisher)

            hashText = ''.join(['{0:02x}'.format(x) for x in hash])
            # print(hashText)
            
            return (hash, hashFunction, hashName, hashText)

        def setHashInDT(hashName, hashText):
            setAttribute(suc, 'hashType', hashName)
            setAttribute(suc, 'hashValue', hashText)

        tamperAppend = random.randbytes(10)

        def finisherChangeFile(hasher):
            if tamperFMU:
                hasher.update(tamperAppend)

        hashNominal, hashFunctionNominal, hashName, hashTextNominal = calculateHash()
        # hashNominal, hashFunctionNominal = updateHashInDT()

        def calculateSignature(hash, hashFunction):
            sigBytes = crypto['leaf']['key'].sign(hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                utils.Prehashed(hashFunction)
            )
            return ''.join(['{0:02x}'.format(x) for x in sigBytes])

        sigLine = calculateSignature(hashNominal, hashFunctionNominal)
        sig = '\n'.join(textwrap.wrap(sigLine, 64))
        # Set the signature to the nominal signature
        setAttribute(suc, 'signature', sig)

        if tamperHash:
            hash, hashFunction, hashName, hashText = calculateHash(finisherChangeFile)
        else:
            hash = hashNominal
            hashFunction = hashFunctionNominal
            hashText = hashTextNominal

        setHashInDT(hashName, hashText)

        soup.smooth()

        # print()
        # print()
        # print(suc.prettify())
        # print(soup.prettify())

        def addStaticContent(zf):
            topDir = os.path.join('boilerplate', 'static')
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
            zf.write(os.path.join('boilerplate', 'generated', 'ca', 'cert.pem'), os.path.join('ca', 'cert.pem'))
            zf.write(os.path.join('boilerplate', 'generated', 'im', 'cert.pem'), os.path.join('im', 'cert.pem'))
            zf.write(os.path.join('boilerplate', 'generated', 'vendor', 'cert.pem'), os.path.join('vendor', 'cert.pem'))
            zf.write(os.path.join('boilerplate', 'generated', 'fmu', 'cert.pem'), os.path.join('fmu', 'cert.pem'))

        def addAMLFile(zf):
            zf.writestr('Test.aml', str(soup).encode('utf-8-sig'))
        
        def addFMUFile(zf):
            with open(fmuFilename, 'rb') as fp:
                fmu = fp.read()
            
            if tamperFMU:
                fmu = fmu + tamperAppend
            
            zf.writestr(os.path.join('src', 'BouncingBall.fmu'), fmu)

        os.makedirs(os.path.join('data', 'tmp'), exist_ok=True)
        with open(os.path.join('data', 'tmp', 'Root.aml'), 'wb') as fp:
            fp.write(soup.prettify().encode('utf-8-sig'))

        with zipfile.ZipFile(filename, 'w', zipfile.ZIP_DEFLATED) as zf:
            addStaticContent(zf)
            addCertificates(zf)
            addAMLFile(zf)
            addFMUFile(zf)

    os.makedirs('fmus', exist_ok=True)
    writeAMLXFile(os.path.join('fmus', 'nominal_fmu.amlx'), False, False)
    writeAMLXFile(os.path.join('fmus', 'broken_fmu.amlx'), True, False)
    writeAMLXFile(os.path.join('fmus', 'tampered_fmu.amlx'), True, True)

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
                exit(1)

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

        log.info('Checking the signature of the certificate')
        amlChain = parseCertificateChain(suc)
        certChain = getRealCertificateChain(amlChain, zf)
        checkSignature(certChain[0], realHashRaw, hashFunction, signature)

        log.error('Not finished implementing')

        log.info('Checking certificate chain')

        log.info('The FMU was successfully checked and seems valid.')

        print('Now the simulation would be run but in the prototype no implementation is made.')

callMap = {
    'bootstrap': runBootstrap,
    'check': runCheck,
}

callMap[args.cmd]()
