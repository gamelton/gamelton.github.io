# Sysadmin notes

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




