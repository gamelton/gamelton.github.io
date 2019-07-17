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
