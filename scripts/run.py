#!/bin/env python

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils

import datetime
import shutil
import os
import zipfile
import re
import textwrap

from pprint import pprint

from bs4 import BeautifulSoup

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

def updateHashInDT():
    def hashBuffer(fp, finisher = None):
        # hashName = 'SHA384'
        hashName = 'SHA256'
        setAttribute(suc, 'hashType', hashName)
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


    with open(os.path.join('boilerplate', 'static', 'src', 'BouncingBall.fmu'), 'rb') as fp:
        hash, hashName, hashFunction = hashBuffer(fp)

    hashText = ''.join(['{0:02x}'.format(x) for x in hash])
    # print(hashText)
    setAttribute(suc, 'hashValue', hashText)

    return (hash, hashFunction)

hash, hashFunction = updateHashInDT()

sigBytes = crypto['leaf']['key'].sign(hash,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    utils.Prehashed(hashFunction)
)
sigLine = ''.join(['{0:02x}'.format(x) for x in sigBytes])
sig = '\n'.join(textwrap.wrap(sigLine, 64))
setAttribute(suc, 'signature', sig)

soup.smooth()

# print()
# print()
# print(suc.prettify())
# print(soup.prettify())

def addAMLFile(zf):
    zf.writestr('Test.aml', str(soup).encode('utf-8-sig'))

os.makedirs(os.path.join('data', 'tmp'), exist_ok=True)
with open(os.path.join('data', 'tmp', 'Root.aml'), 'wb') as fp:
    fp.write(soup.prettify().encode('utf-8-sig'))

with zipfile.ZipFile('test.amlx', 'w', zipfile.ZIP_DEFLATED) as zf:
    addStaticContent(zf)
    addCertificates(zf)
    addAMLFile(zf)
