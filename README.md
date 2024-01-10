# dcsyncdpapikey

This script dumps the domain backup keys via DRSUAPI (DCSync). The heavy lifting is all done with impacket, so this
needs to be installed. The script extracts the required information from LDAP (objectclass=secret) and calls the
relevant DCSync Operation with the GUID of the secret object.

# Usage

```
# full chain

python3 dcsyncdpapikey.py domain/user:'pw'@target

# just dump GUIDS for backupkey via LDAP with a admin account, useful for OPSEC if you want to dcsync with DC machine hash

python3 dcsyncdpapikey.py domain/user:'pw'@target -ldap-only

# dump key via DCSync with extracted GUID

python3 dcsyncdpapikey.py domain/DC\$@target -hashes :hash -key-only --guid GUID

```



# Credits

@SecureAuthCorp for their Impacket project, which this entire project utilizes to interact with windows services: https://github.com/SecureAuthCorp/impacket
