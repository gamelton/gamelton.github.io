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
1. Azure AD User has directory role Report Reader
1. Application right Read all audit log data
1. ADAL v3 

Preparation:
1. Run PowerShell command to install ADAL module
   >Install-Package ADAL.PS
1. Get Tenant ID that is Directory ID from Azure AD properties at https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Properties
1. Register application for you Azure AD at https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/RegisteredAppsPreview
   1. Get Application (client) ID from Application properties
   1. Make sure to check under app's Authentication Default client type Yes (Application is public client)
   1. Make sure to grant API permission of AuditLog.Read.All to the application 

[Repository](https://github.com/gamelton/Azure-AD-Failed-Sign-ins)

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
When you use resouce mailbox you can set it to auto accept all incoming meeting invitations. It stores accept answer in Sent Items folder. And it stores checked invittation in Deleted Items folders. Which piles up as usually resource mailbox isn't manually accessed. So to auto deletes items in these folders we could set up Retention Policy. Excample commands run in Exchange Shell.
1. First we create two tags: for Sent and for Deleted items.
   > New-RetentionPolicyTag "RPT-PermanentlyDelete-DeletedItems" -Type DeletedItems -RetentionEnabled $true -AgeLimitForRetention 1 -RetentionAction PermanentlyDelete
   > New-RetentionPolicyTag "RPT-PermanentlyDelete-SentItems" -Type SentItems -RetentionEnabled $true -AgeLimitForRetention 1 -RetentionAction PermanentlyDelete
1. Then we link them to Retention Policy. 
   > New-RetentionPolicy "RP-MeetingRooms" -RetentionPolicyTagLinks "RPT-PermanentlyDelete-DeletedItems","RPT-PermanentlyDelete-SentItems"
1. Then we apply the policy to Resource Mailbox.
   > Set-Mailbox "meetingroom" –RetentionPolicy "RP-MeetingRooms"
1. After some time Managed Folder Assistant (MFA) runs and tags all messages in these folders. Those expired got Permanently Deleted (you could change this in `RetentionAction` parameter). 
