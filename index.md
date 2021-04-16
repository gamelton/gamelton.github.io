# Sysadmin notes

For feedback please [create an issue](https://github.com/gamelton/gamelton.github.io/issues)


# LastPass Failed Logins
Get LastPass failed logins from API

Use LastPass Enterprise API to get failed logins. Info from last 7 days, you could change it inside the script.

Prerequisites:
1. Get your URL, CID and provisioning hash from Admin console at https://lastpass.com/company/#!/settings/enterprise-api

[Repository](https://github.com/gamelton/LastPass-Failed-Logins)

# Azure AD Failed Sign-ins
Get Azure Active Directory failed sign-ins from Graph API

Query Microsoft Graph API for incorrect login or password sign-ins. We filter for specifit Event ID of **50126** that's `Invalid username or password`. You could change this inside the script. The script uses Azure AD user's credentials in clear text, so make sure it's stored properly.

Prerequisites:
1. Azure Active Directory premium 1 (P1) license
1. Azure AD User has Report Reader directory role
1. Application has specific API permission
1. ADAL v3 

Preparation:
1. Run PowerShell command to install ADAL module
   >Install-Package ADAL.PS
1. Get Tenant (Authority) ID that is Directory ID from Azure AD properties at https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Properties
1. Create Azure AD user and assign him Report Reader role 
1. Register application for you Azure AD at https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/RegisteredAppsPreview
   1. Get Application (Client) ID from Application properties
   1. Make sure to check under app's Authentication Default client type Yes (Application is public client)
   ![AzureAD App Public Client](/images/azuread-app-registration-01.PNG)
   1. Make sure to grant API permission to the application
      1. AuditLog.Read.All 
      1. Directory.Read.All
      Note: You would need to press grant admin consent button to apply for the organization.
      ![AzureAD App API Permission](/images/azuread-app-registration-02.PNG)
1. Edit the script and supply your
   1. `TENANTID` and `CLIENTID`for Tenant (Authority) and Application (Client)
   1. `AZUREADUSERLOGIN` and `AZUREADUSERPASSWORD` for Azure AD User with correct role

[Repository](https://github.com/gamelton/Azure-AD-Failed-Sign-ins)

# Microsoft Graph API REST Powershell
[Previous Graph API interaction sometimes doesn't work](https://gamelton.github.io/#azure-ad-failed-sign-ins). Thanks to [Alex Asplund](https://adamtheautomator.com/microsoft-graph-api-powershell/) I was able to write the simplier script that doesn't require Azure AD user.

Get Azure Active Directory failed sign-ins and security alerts from Graph API.
Three querries. You could change them and specific details or add new.
1. Query for [security alerts](https://docs.microsoft.com/en-us/graph/api/alert-list) over last week.
1. Query for [incorrect login or password sign-ins](https://docs.microsoft.com/en-us/graph/api/signin-list) over last week. Filter for specifit Event ID of **50126** that's `Invalid username or password`.
1. Query for sign-ins with `atRisk` state over last week. This might include same events as first query.
1. Put each query's result into html file. The path is absolute.
1. Combine files and send them via email.
1. This script is run as Scheduled Job once a week.

Requirements:
1. Azure Active Directory premium 1 (P1) license
1. Application has specific API permission
1. Application has secret (password)

Preparation:
1. Get Tenant (Authority) ID that is Directory ID from Azure AD
1. Register application for you Azure AD
   1. Get Application (Client) ID from Application properties
   1. Make sure to grant API permission to the application
      1. AuditLog.Read.All 
      1. Directory.Read.All
      1. SecurityEvents.Read.All

      Note: You would need to press grant admin consent button to apply for the organization.

   1. Generate application secret.

   Note: You should save it immediately as it won't be shown again
   ![AzureAD App Secret](/images/azuread-app-registration-03..PNG)

1. Edit the script and supply your
   1. `TENANTID` for Tenant (Authority)
   1. `CLIENTID` and `APPPASSWORD` for Application (Client) ID and secret
   1. `AZUREADUSERLOGIN` and `AZUREADUSERPASSWORD` for Azure AD User with correct role
   1. `SECURITYALERTS\PATH.HTML`, `FAILEDLOGIN\PATH.HTML` and `LOGINWITHATRISK\PATH.HTML`for HTML files.
   1. `FROMEMAIL@ADDRESS`, `TOEMAIL@ADDRESS` and `MAIL.SERVER` to send generated email
   
[Repository](https://github.com/gamelton/Microsoft-Graph-API-REST-Powershell)

# Unencrypted LDAP Binds
Get Active Directory unencrypted LDAP binds

Active Directory Domain Controllers uses three protocols for authentication: Kerberos, NTLM and LDAP. For Windows native applications usually first two are used. They are secured by encryption. LDAP protocol authentication is used usually by non-native apps like Java. By default configuration Windows domain controller allows unencrypted LDAP binding. That means all messages are sent in clear text including login and password.
You could change time inside the script from last 24 hours.

You could configure Event Log to store every such binding:
1. Open registry editor on domain controller
   > HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics
1. Change `16 LDAP Interface Events` value to **2**
1. You could see Event ID `2889` pops up in
   > Event Viewer -> Applications and Services Logs -> Directory service

You may need to increase Maximum log size in order to accomodate all events comming to it after you enabled Active Directory Diagnostic Event Logging.

[Repository](https://github.com/gamelton/Unencrypted-LDAP-Binds)

# Get LDAPS server certificate
When you don't know which certificate Active Directory sends when you LDAPS connect to it. There are some options, like running network packet capture. Or you could use OpenSSL client to grab it from the handshake. Just connect to Domain Controller on LDAPS port.

   > openssl s_client -connect domain-controller.domain:636

1. Part of the output of this file will be the Base-64 encoded .cer file that was presented for LDAPS.
1. Just cut and paste into notepad beginning at "--Begin Certificate--" through "---End Certificate---"  and save as a .cer
1. Double-click on the certificate file and you will now be viewing the certificate presented for LDAPS.

# SCOM monitor file modification

WMI allows you to check for the events like file modification. You could run a notification query that gets result when an event happens. You could monitor different evetns like program run, or file modified. SCOM has WMI event subsystem that can help monitor such events.

You could test your WMI query
1. Run wbemtest.exe
1. Connect to root\cimv2
1. Push notification query
1. Enter your WMI query and press Apply
   F.x. monitor for program run
   > SELECT * FROM __InstanceCreationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'notepad.exe'
   
   ![wbem](/images/wbem-notepad-edited.png)

Create SCOM monitor:
1. Authoring-> Management Pack Objects -> Monitors
1. Create a Monitor -> Unit Monitor
1. Select the type of monitor -> WMI Events -> Simple Event Detection -> Manual Reset

   ![SCOM WMI Unit Monitor](/images/scom-wmi-unit-monitor.PNG)

1. Select management pack -> Overrides management pack.
1. Next.
1. Name -> file modification monitor, Monitor target -> Windows computer, Parent monitor -> Availability. Uncheck monitor is enabled. We'll enable monitor only for specific group of computers.
1. Next.
1. Type WMI Namespace `root\cimv2`. And the query.
1. Next.
1. Put any Filter.
The wizard for creating a WMI Event monitor/rule actually won't let you specify no criteria.  The Next button won't be active until you provide some entry.  If you have a query that doesn't need any filter (which is entirely reasonable), then just specify some bogus filter.  Once the monitor/rule is created, open up its properties and delete the filter.  It's entirely valid to have a monitor/rule with no filter - the wizard just doesn't let you do it.
1. Generate alerts for this monitor. Set alert description.
1. Create.
1. Go to Authoring -> Groups. Create group.
1. Management pack -> Overrides Management Pack.
1. Next.
1. Add Explicit Group Members. Search for objects of Windows Computer type. This computers will have monitor enabled for them.
1. Next.
1. Search Monitors for created monitor. Right click -> Overrides -> Override the Monitor -> For a group.
1. Select created group.
1. In Override Properties. Check Enabled -> True.
1. Check that computer now has this monitor. Go to Monitoring -> Windows Computers.
1. Right click on computer -> Open -> Health Explorer.
1. Open Availability -> monitor name -> State Change Events.


More info https://docs.microsoft.com/en-us/previous-versions/technet-magazine/cc160917(v=msdn.10)

[Repository](https://github.com/gamelton/WMI-File-Modification)

# Exchange retention policy for resource mailbox
When you use resouce mailbox you can set it to auto accept all incoming meeting invitations. It stores accepted answer in Sent Items folder. And it stores checked invitation in Deleted Items folders. Which piles up as usually resource mailbox isn't manually accessed. So to auto delete items in these folders we could set up Retention Policy. Example commands run in Exchange Shell.
1. First we create two Retention Policy Tags(RPT): for Sent and for Deleted items.
   > New-RetentionPolicyTag "RPT-PermanentlyDelete-DeletedItems" -Type DeletedItems -RetentionEnabled $true -AgeLimitForRetention 1 -RetentionAction PermanentlyDelete
   
   > New-RetentionPolicyTag "RPT-PermanentlyDelete-SentItems" -Type SentItems -RetentionEnabled $true -AgeLimitForRetention 1 -RetentionAction PermanentlyDelete
1. Then we link them to Retention Policy. 
   > New-RetentionPolicy "RP-MeetingRooms" -RetentionPolicyTagLinks "RPT-PermanentlyDelete-DeletedItems","RPT-PermanentlyDelete-SentItems"
1. Then we apply the policy to Resource Mailbox.
   > Set-Mailbox "meetingroom" –RetentionPolicy "RP-MeetingRooms"
1. After some time Managed Folder Assistant (MFA) runs and tags all messages in these folders. Those expired got Permanently Deleted (you could change this in `RetentionAction` parameter). 

# DNS Host name restriction
DNS names (this also includes A/AAAA) may only contain `[0-9]`, `[a-z]`, `-`, so the underscore is not valid. Note that a TXT record is not a hostname, and this restriction doesn't apply for it. And one last edit: may not be used as the first character either.
More info https://en.wikipedia.org/wiki/Hostname#Restrictions_on_valid_hostnames

# Juniper JunOS port reset
When client closes the conneciton, TCP packet with RST flag is sent. By default JunOS waits 2 seconds before the port is closed. This could be an issue when cilent establishes new TCP connection from the same source port, that's marked for closing by Juniper. The following configuration command will force JunOS to close port instantly
> set security flow tcp-session rst-invalidate-session

# Juniper JunOS application traffic inspection
Juniper checks traffic on well-known port for compliance with protocol that is expected to flow on that port. If you send one protocol over port reserved for another protocol, Juniper will block it. F.x. TCP port 2000 is used by Cisco SCCP skinny protocol. If you send HTTP traffic over TCP 2000 it's not passed. You could disable protocol traffic inspection (ALG) per protocol.
> set security alg sccp disable

On Cisco router the commands should be
> no ip inspect name myfw skinny

> no ip nat service skinny tcp port 2000

# Sort Powershell object properties
By default Powershell doesn't sort object properties. Which is confusing when object has a lot of properties. And you look trough all of them. This is an example command to sort AD user object properties by their name.
> $(Get-ADUser -Identity user -Properties \*).PsObject.Properties \|  select Name, Value \| sort Name

# SSL verification mode
Some network services allow configuration of how certificates are verified. This is due to the multiple purposes of TLS: authentication and encryption. Authentication means you trust host you connect to. Encryption means messages are not sent in clear text. If TLS connection is made between trusted parties in secured network it might be handy to disalbe authentication part. This is due to major use of self-signed certificates that stops connection establishment if certificate could not be verified.
General mode description (taken from Elasticsearch doc):
1. `full`, which verifies that the provided certificate is signed by a trusted authority (CA) and also verifies that the server’s hostname (or IP address) matches the names identified within the certificate.
1. `certificate`, which verifies that the provided certificate is signed by a trusted authority (CA), but does not perform any hostname verification.
1. `none`, which performs no verification of the server’s certificate.

# MBAM Recovery Key SQL query
MBAM is Bitlocker drive encryption solution. It allows you to retrieve Recovery Key from web portal. It requires you to provide Key ID. That's not always optimal in case you need to provide recovery key but don't have access to the machine. You could run SQL script against `MBAM Recovery and Hardware` databse. This example return Recovery Key for machine with hostname `machinename`.
>SELECT M.\[Id],M.\[Name],MV.\[VolumeId],K.\[RecoveryKeyId],K.\[RecoveryKey]

>FROM \[RecoveryAndHardwareCore].\[Machines] M

>LEFT JOIN \[RecoveryAndHardwareCore].\[Machines_Volumes] MV ON M.\[Id]=MV.\[MachineId]

>LEFT JOIN \[RecoveryAndHardwareCore].\[Keys] K ON MV.\[VolumeId]=K.\[VolumeId]

>WHERE M.\[Name] like '%machinename%'

# Two types of email address
An email message may contain multiple originator, or sender, addresses. 
1. `Mail From` address: Identifies the sender and specifies where to send return notices if any problems occur with the delivery of the message, such as non-delivery notices. This appears in the envelope portion of an email message and **is not usually displayed** by your email application. This is sometimes called the 5321.MailFrom address or the reverse-path address.
1. `From` address: The address displayed as the From address by your mail application. This address identifies the author of the email. That is, the mailbox of the person or system responsible for writing the message. This is sometimes called the 5322.From address.

# Change MS Teams email address
If you have Azure AD Connector to sync your on-premise users and groups to Office 365 cloud. Sometimes you create on-premise group that has the same email address as Teams/Office365 cloud group. In that case you'll get a sync error of `Duplicate Attribute Error`. You could change email address of the cloud group to resolve the sync issue.
Connect to Exchange Online using [Exchange PowerShell V2 module](https://aka.ms/exops-docs)

>Set-UnifiedGroup -Identity "Cloud group name" -EmailAddresses: @{Add ="newcloudgroup@email.address"}

>Set-UnifiedGroup -Identity "Cloud group name" -PrimarySmtpAddress "newcloudgroup@email.address"

>Set-UnifiedGroup -Identity "Cloud group name" -EmailAddresses: @{Remove="oldcloudgroup@email.address"}

# Juniper site-to-site VPN identification
With IPSEC vpn there is always a proxy-id pair sent.  This is part of the standard.
When you don't explicitly configure one on the SRX it will us 0.0.0.0/0 to 0.0.0.0/0 meaning any subnet can be sent or recieved on the tunnel.

This is the recommended and simpliest path.
But most other vendors do not allow this open proxy pair.  So we must configure explict pair(s) for compatibility and for the tunnel to come up.

Unfortunately, the proxy id method only supports a single pair.  If you have multiple pairs your only option is either policy vpn or traffic selectors.

* `proxy id` allows only one pair
* `traffic selectors` allow more that one pair

> security ipsec vpn ike proxy-identity \[local | remote\]  
> security ipsec vpn traffic-selector

# The built-in Administrator account
The local Administrator account (RID -500) is disabled by default on Windows 10 but not on Windows Server. When installing Windows 10, Windows Setup prompts you for a new account which becomes the primary administrative account for the computer. By contrast, Windows Server’s setup prompts you for a new password for the Administrator account.

The main differences between the built-in -500 Administrator account (when enabled) and a custom administrative local account are
1. the -500 account is not subject to account lockout, account expiration, password expiration, or logon hours
1. the -500 account cannot be removed from the Administrators group
1. by default the -500 account always runs with full administrative rights without UAC prompts, including over the network. This third difference can be removed by enabling the security option, “User Account Control: Admin Approval Mode for the Built-in Administrator account.”

# Network route distance and pririty
Each network route has its distance and priority. Usually put in brackets.

`0.0.0.0/0 [5/0] via 192.168.1.1`

If multiple routes exist for the same destination, only one route is selected into routing table.

The rules for preferred route:
* If multiple routes to the same destination have the same priority but different distances, the route with the lowest distance is used.
* If multiple routes to the same destination have the same distance but different priorities, the route with the lowest priority is used.
* Distance takes precedence over priority. If multiple routes to the same destination have different distances and different priorities, the route with the lowest distance is always used even if it has the highest priority.

If two routes have the same administrative distance and the same priority, then they are equal cost multipath (ECMP) routes. Then you should configure load balancing with ECMP routes.

# ulimit recommendation for Solr
These four settings in particular are important to have set very high, unlimited if possible.

* max processes (`ulimit -u`): 65,000 is the recommended minimum.
* file handles (`ulimit -n`): 65,000 is the recommended minimum. All the files used by all replicas have their file handles open at once so this can grow quite large.
* virtual memory (`ulimit -v`): Set to unlimited. This is used to by MMapping the indexes.
* max memory size (`ulimit -m`): Also used by MMap, set to unlimited.
* If your system supports it, `sysctl vm.max_map_count`, should be set to unlimited as well.

# Active DIrectory Certificate Services notes
Couple of notes on certificate properties

`NewRequest`

* `Exportable`
    If private key could be exported.
    
* `Subject`
    Because SSL/TLS does not require a Subject name when a SAN extension is included, the certificate Subject name can be empty. So you could any text to it.
    
* `MachineKeySet`
    Save certificate to Machine certificate store
    
* `KeySpec`
    Most of the time you needd Key Exchange
    * `AT_KEYEXCHANGE (or KeySpec=1)` RSA key that can be used for signing and decryption
    * `AT_SIGNATURE (or KeySpec=2)` RSA signature only key
    
* `KeyUsage`
    Restriction on how key could be used
    * `CERT_DIGITAL_SIGNATURE_KEY_USAGE` for TLS certificate. The key is used with a Digital Signature Algorithm (DSA) to
    * `CERT_KEY_ENCIPHERMENT_KEY_USAGE` for TLS certificate. The key is used for key transport. 
    * 
    * `CERT_KEY_CERT_SIGN_KEY_USAGE` for CA certificate
    * `CERT_CRL_SIGN_KEY_USAGE` for CA certificate
    * `CERT_OFFLINE_CRL_SIGN_KEY_USAGE` for CA certificate
    
`BasicConstraintsExtension`

* `PathLength`
    For Certificate Authority certificate this is Key Constraint. It sets how many levels below CA allowed to issue CA certificate. That is if the second level CA is allowed to issue certificate to other CA. That restricts number of CA levels.
    
`ExtendedKeyUsageExtension`
* `OID` = 1.3.6.1.5.5.7.3.1 ; Server Authentication
* `OID` = 1.3.6.1.5.5.7.3.2 ; Client Authentication


    
`Extensions`
* `2.5.29.17 = "{text}"`
* `_continue_` = "DNS=www.example.ord&"
* `_continue_` = "IPAddress=1.1.1.1"
Note the ampersand \(&\), it should be appended inside quotes to each SAN  except the last
Note first text line should be in request
    * `Subject Alternative Name`
    In Microsoft SAN could be changed in two ways:
        * Certificate Attributes. For this you issue command on CA that enables appending SAN to certificate request. This is not secure. Because it works on CA server scope for all certificate issued by that CA. And because the requested certificate is not the same as issued certificate. This works by geting certificate request in AD CS Web Enrollement page and fill in Attributes field what SAN you want.
        * Request Properties. This is prefferebale. But this requires using 'policy inf' file. That way you create certificate request with included SAN. So no need to additinally add anything to that request later.
    


    
 
Show Machine store Personal certificates

> certutil -store -v My


Create certificate request with policy file
    
> certreq -new policyfile.inf myrequest.req


**Warning!** Usanfe command to turn on SAN attribute for all certificates issued by CA

> certutil -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2

Adding a SAN attribute to the RequestAttributes section of RequestPolicy.inf also requires that the CA is configured to accept SAN attributes by enabling EDITF_ATTRIBUTESUBJECTALTNAME2, which can put your PKI at risk for impersonation attacks.
Whenever possible, specify SAN information by using certificate extensions instead of request attributes to avoid enabling EDITF_ATTRIBUTESUBJECTALTNAME2.
Do not enable EDITF_ATTRIBUTESUBJECTALTNAME2 on an enterprise CA. 





# IPv6 issues

* Colon `(:)` characters in IPv6 addresses may conflict with the established syntax of resource identifiers, specifically port number.

* With link-local addresses the address prefixes may still be identical for different interfaces, which makes the operating system unable to select an outgoing interface based on the information in the routing table (which is prefix-based). To resolve this in textual addresses, a interface index must be appended to the address, the two separated by a percent sign `(%)`. When used in uniform resource identifiers (URI), the use of the percent sign causes a syntax conflict.




# curl download Java Cryptography Extension (JCE)
> curl -q -L -C - -b "oraclelicense=accept-securebackup-cookie" -o jce_policy-8.zip -O http://download.oracle.com/otn-pub/java/jce/8/jce_policy-8.zip 




# UEFI booting
Unlike the legacy PC BIOS, UEFI does not rely on boot sectors, defining instead a boot manager as part of the UEFI specification. When a computer is powered on, the boot manager checks the boot configuration and based on its settings, loads into memory and then executes the specified OS boot loader or operating system kernel. The boot configuration is defined by variables stored in NVRAM, including variables that indicate the file system paths to OS loaders or OS kernels. 
OS boot loaders can be automatically detected by UEFI, which enables easy booting from removable devices such as USB flash drives. This automated detection relies on standardized file paths to the OS boot loader, with the path varying depending on the computer architecture. The format of the file path is defined as `<EFI_SYSTEM_PARTITION>\EFI\BOOT\BOOT<MACHINE_TYPE_SHORT_NAME>.EFI`
Windows loader path
`\EFI\MICROSOFT\BOOT\BOOTMGFW.EFI`
The EFI system partition, often abbreviated to ESP, is a data storage device partition that is used in computers adhering to the UEFI specification. Accessed by the UEFI firmware when a computer is powered up, it stores UEFI applications and the files these applications need to run, including operating system boot loaders.
For use on ESPs, UEFI defines a specific version of the FAT file system, which is maintained as part of the UEFI specification and independently from the original FAT specification, encompassing a variant of the FAT32 file system on ESPs.



# Windows Authentication Options
When connecting to a Windows host, there are several different options that can be used when authenticating with an account.

| Option      | Local Accounts |  Active Directory Accounts | Credential Delegation | HTTP Encryption |
| ----------- | ----------- | ----------- | ----------- | ----------- |
| Basic       | Yes       | No       | No       | No       |
| Certificate | Yes        | No        | No        | No        |
| Kerberos    | No        | Yes        | Yes        | Yes        |
| NTLM        | Yes        | Yes        | No        | Yes        |
| CredSSP     | Yes        | Yes        | Yes        | Yes        | 



# SMTP AUTH
'SMTP AUTH' is often assumed to be synonymous with `SMTP with Basic Authentication` but it isn’t. SMTP AUTH (RFC 4954) in particular does not specify an authentication method but merely provides a simple protocol (SASL) bolted on to SMTP for incorporating such a method. So any enable/disable  setting switch entitled 'SMTP AUTH' must either also specify an associated authentication method or be assumed to apply to all methods (hence 'blocked at the protocol level').



# PowerShell match operator
The `-match` operator works in 2 different modes, depending on what's being matched. If it's a scalar (single value) it will return a boolean ($true or $false). If it's an array, it will return all members of the array that satisfy the match.

# Microsoft Graph API Authntication method flows
You can only authenticate using oauth athentication as Microsoft deprecated basic auth on November 1st 2018.

There are currently three authentication methods:

- [Authenticate on behalf of a user](https://docs.microsoft.com/en-us/graph/auth-v2-user?context=graph%2Fapi%2F1.0&view=graph-rest-1.0): 
Any user will give consent to the app to access it's resources. 
This oauth flow is called **authorization code grant flow**. This is the default authentication method used by this library.
- [Authenticate on behalf of a user (public)](https://docs.microsoft.com/en-us/graph/auth-v2-user?context=graph%2Fapi%2F1.0&view=graph-rest-1.0):
Same as the former but for public apps where the client secret can't be secured. Client secret is not required.
- [Authenticate with your own identity](https://docs.microsoft.com/en-us/graph/auth-v2-service?context=graph%2Fapi%2F1.0&view=graph-rest-1.0): 
This will use your own identity (the app identity). This oauth flow is called **client credentials grant flow**. 

    > 'Authenticate with your own identity' is not an allowed method for **Microsoft Personal accounts**. 



| Topic                      | On behalf of a user                                      | On behalf of a user (public)                               | With your own identity |
| ---------------------------| -------------------------------------------------------- | ---------------------------------------------------------- |------------------------|
|**Register the App**        | Required                                                 | Required                                                   | Required|
|**Requires Admin Consent**  | Only on certain advanced permissions                     | Only on certain advanced permissions                       | Yes, for everything|
|**App Permission Type**     | Delegated Permissions (on behalf of the user)            | Delegated Permissions (on behalf of the user)              | Application Permissions|
|**Auth requirements**       | Client Id, Client Secret, Authorization Code             | Client Id, Authorization Code                              | Client Id, Client Secret|
|**Authentication**          | 2 step authentication with user consent                  | 2 step authentication with user consent                    | 1 step authentication|
|**Auth Scopes**             | Required                                                 | Required                                                   | None|
|**Token Expiration**        | 60 Minutes without refresh token or 90 days              | 60 Minutes without refresh token or 90 days                | 60 Minutes|
|**Login Expiration**        | Unlimited if there is a refresh token and as long as a refresh is done within the 90 days| Unlimited if there is a refresh token and as long as a refresh is done within the 90 days| Unlimited|
|**Resources**               | Access the user resources, and any shared resources      | Access the user resources, and any shared resources        | All Azure AD users the app has access to|
|**Microsoft Account Type**  | Any                                                      | Any                                                        | Not Allowed for Personal Accounts|
|**Tenant ID Required**      | Defaults to "common"                                     | Defaults to "common"                                       | Required (can't be "common")|

# Office 365 consumed license Python
[Similar to Powerhell access to Microsoft Graph API](https://gamelton.github.io/#microsoft-graph-api-rest-powershell). This is an example task of finding Office 365 license consumption. It's a bare minimum Python script that has hardcoded SKU ID of the license of interest. It outputs just one number of consumed licenses of that SKU. It uses specific URL `https://graph.microsoft.com/v1.0/subscribedSkus/{SKU-ID}` to get information on specific license SKU. It authenticates with your own identity this will use your own identity (the app identity). This oauth flow is called `client credentials grant flow`.

Prerequesities:
1. Python 3
1. Python module requests
   On Ubuntu you could install module by running
   > apt install python3-pip
   
   > pip3 install requests
1. Azure Active Directory premium 1 (P1) license
1. Application has specific API permission

   `Organization.Read.All`, `Directory.Read.All`
1. Application has secret (password)

Preparation:
1. Get Tenant (Authority) ID that is Directory ID from Azure AD
1. Register application in [Azure Portal (App Registrations)](https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade)
   1. Get Application (Client) ID from Application properties
   1. Switch off `Allow public client flows`
   1. Under "Certificates & secrets", generate a new client secret. Set the expiration preferably to never.
      
      Note: You should save it immediately as it won't be shown again

   1. Under Api Permissions add the application permissions for Microsoft Graph you want
      1. Organization.Read.All 
      1. Directory.Read.All

      Note: You would need to press grant admin consent button to apply for the organization.
      
1. Edit the script and supply your
   1. `TENANT-ID` for Tenant (Authority) ID
   1. `APP-ID` and `APP-SECRET` for Application (Client) ID and secret
   1. `SKU-ID` for SKU license which you would like to get the consumption
   
   You could get the list of all SKUs and look for the ID you want by listing all SKU on the tenant
   
   ```python
   skusurl = 'https://graph.microsoft.com/v1.0/subscribedSkus'
   skusrequest = requests.get(skusurl, headers=tokenheader)
   skusrequest.text
   ```

1. Make script executable
   > chmod +x get-office365-consumed-license.py

[Repository](https://github.com/gamelton/Microsoft-Graph-API-REST-Python)


# MS SQL login and user account

**Authentication** is the process of proving the user is who they claim to be. A user connects to a database using a user account.
When a user attempts to connect to a database, they provide a user account and authentication information. The user is authenticated using one of the following two authentication methods:

- SQL authentication.

  With this authentication method, the user submits a user account name and associated password to establish a connection. This password is stored in the master database for user accounts linked to a login or stored in the database containing the user accounts *not* linked to a login.
- Azure Active Directory Authentication

  With this authentication method, the user submits a user account name and requests that the service use the credential information stored in Azure Active Directory (Azure AD).

**Logins and users**: A user account in a database can be associated with a login that is stored in the master database or can be a user name that is stored in an individual database.

- A **login** is an individual account in the master database, to which a user account in one or more databases can be linked. With a login, the credential information for the user account is stored with the login.
- A **user account** is an individual account in any database that may be, but does not have to be, linked to a login. With a user account that is not linked to a login, the credential information is stored with the user account.



# Powershell domain password change with LDAP  

First example scenario shows how to test password for domain user using LDAP  
Second example scenario shows how to reset password for domain user using LDAP  

Long version description scenario  
   Suppose a user lost his domain account password. He can't get in internal network. He needs to have his domain user account password reset.  
   The script is one way of doing it. It uses Powershell and LDAP connection. Note: it's security issue, the script holds clear text password, LDAP sends in clear text.  

The flow description

- User logins to domain as temporary test.shared.user1 account in Powershell

- User uses standalone machine not-joined to domain

- User changes password for his test.changed.user2 account


Test flow preparation  

1. Create domain user `test.shared.user1`  
   This is used for temporary login
  
1. Create domain user `test.changed.user2`  
   This is user's forgotten account
  
1. Grant access rights on `test.changed.user2`  
   Open Active Directory Users and Computers  
   Select View -> Checkbox Advanced features  
   Select `test.changed.user2` -> Properties 
   Go to Security -> Advanced -> Add  
   Select a principal -> `test.shared.user1`  
   Type -> Allow  
   Applies to -> This object only  
   Persmissions -> `Reset password`, `Change password`  
   Properties -> `Write lockoutTime`, `Write pwdLastSet`  
   Apply -> OK -> OK  


Test-LDAP-Credentials.ps1  

- Change `$userName = "test.changed.user2"`  
- Change `$userPassword = "P@ssword2"`  
- Chnage `$userDomain = "ad.domain.com"`  
- Change `$serverDC = "dc.ad.domain.com"`  
   After run script says True if password is correct  

Reset-LDAP-Password.ps1  

- Change `$userSharedName = "test.shared.user1"`  
- Change `$userSharedPassword = "P@ssword1"`  
- Change `$userChangedName = "test.changed.user2"`  
- Change `$userChangedPassword = "P@ssword2"`  
- Change `$serverLDAP = "LDAP://dc.ad.domain.com:389/DC=ad,DC=domain,DC=com"`  
   After run script user `test.changed.user2` has password P@ssword2  


[Repository](https://github.com/gamelton/Powershell-Change-Domain-Password-LDAP)


# Powershell secure string cleartext  
Couple of examples where you could get clear text for Secure String in Powershell  

```powershell
$Credentials = Get-Credential -Message "Enter domain, user name and old password"`
$Credentials.GetNetworkCredential().password
```

```powershell
$Password = Read-Host -AsSecureString -Prompt 'Enter new password'
[System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))
```

# Web shell attack mitigation practicies
Web shells are malicious files or code snippets that attackers put on compromised web servers to perform arbitrary, attacker-specified actions on the system or return requested data to which the system has access  
- Deploy the latest security updates as soon as they become available  
- Implement proper segmentation of your perimeter network, such that a compromised web server does not lead to the compromise of the enterprise network  
- Users should only be able to upload files in directories that can be scanned by antivirus and configured to not allow server-side scripting or execution  
- Audit and review logs from web servers  
- Use firewall to prevent command-and-control server communication among endpoints whenever possible, limiting lateral movement  
- Check your perimeter firewall and proxy to restrict unnecessary access to services, including access to services through non-standard ports  
- Limit the use of accounts with local or domain admin level privileges  
- Check server log for requests from IP address outside the normal subnet  
- Check log forunexpected network flows. F.x. web server makes web requests to internal network nodes. F.x. non-web server node (e.g., a network device) suddenly is responding to a web requests from outside the network  
- Check for process run by web server. F.x. web server usually don't run ping. Windows processes  


# Graylog API get unique field value
Graylog is a tool to collect and centrally store logs. It could be used from web dashboard to search through stored messages. It uses Elasticsearch and thus supports Lucenene query language. It's case sensitive. But for advanced queries it might miss some functionality. That's where Graylog API comes into place. Since Graylog version 4 its API was changed, this example uses this version. It provides first how to run search in API through web GUI. Second, how to run search in API through Powershell.  
We will be looking through collected Windows logs. For `An account was successfully logged on` event. For specific period of time. And then from `IpAddress` field we extract unique value and count how many times login was used for each IP address.

## API search in web UI
To connect to the Graylog REST API with a web browser, just add ``api/api-browser`` to your current ``http_publish_uri`` setting or use the **API browser** button on the nodes overview page (*System / Nodes* in the web interface).  
For example if your Graylog REST API is listening on ``http://192.168.178.26:9000/api/``, the API browser will be available at ``http://192.168.178.26:9000/api/api-browser/``.  
After providing the credentials (username and password), you can browse all available HTTP resources of the Graylog REST API.  
Find ``Search`` and ``/views/search/sync``, put JSON query in Search box and push `Try it out` button.  
**Example query for successfull logins**  
- EventID:4624  
- time from 2021-03-03 07:00:00.000  
- time to 2021-03-03 07:15:00.000  

```json
{
  "queries": [
    {
      "id": "qid",
      "timerange": {
          "type": "absolute",
          "from": "2021-03-03T07:00:00.000Z",
          "to": "2021-03-03T07:15:00.000Z"
       },
      "query": {
        "type": "elasticsearch",
        "query_string": "EventID:4624"
      },
      "search_types": [{
            "timerange": null,
            "query": null,
            "streams": [],
            "id": "stid",
            "name": null,
            "limit": 150,
            "offset": 0,
            "sort": [
              {
                "field": "timestamp",
                "order": "DESC"
              }
            ],
            "decorators": [],
            "type": "messages",
            "filter": null
          }]
    }
  ]
}
```
## API search in Powershell
For more advaced search let's store query body in a file. And run Powershell command `Invoke-RestMethod`.  
Notes to body file    
- `query_string` - this is query you normailly put in Search box in web dashboard. It needs backslash for escape double quotes. We filter internal IPs because we are not interested in them  
- `row_groups` - provides field name we group on. And how many results returned (100)  
You could see JSON body file in [Repository](https://github.com/gamelton/graylog-api-unique-field-value)  

Notes to command  
- Basic authentication sends credentials in cleartext  
- Replace `user` and `password` with your Graylog user  
- You could create access tokens which can be used for authentication instead. Navigate to the users configuration menu ``System / Authentication`` for that  
- Change `192.168.178.26` to your Graylog IP address  
- Chnage `C:\Users\username\graylog=body-request.json` to your JSON body file  
- Script connects to `ip-api` service to get country and organization info. Free plan throttles requests. So workaround is `Start-Sleep -s 4` to pause on each IP address. Expect this command to run long time  

You could see Powershell script file in [Repository](https://github.com/gamelton/graylog-api-unique-field-value)  



# Kaspersky Open API
Kaspersky Security Center has Open API that understands web requests. By default it's running on port `13299`  
This is exemple to get used license on specific license key  

Notes to command  
- Replace `username` and `password` with your Kaspersky user  
   You could use local admin user on the Kasperky server  
- `username` and `password` are base64 encoded  
- Replace `kaspersky-server-address` with your Kaspersky server addresss  
- You run script with argument key id. That argument then used in `licenseid` variable  
   You could gey key number from Kaspersky Security Center MMC
- Output number of licenses used on the key  

You could see Python script file in [Repository](https://github.com/gamelton/kaspersky-open-api-python)  

