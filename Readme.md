# Microsoft Defender 365 Advanced hunting full schema reference (Streaming API overview)

[MS 365 Advanced hunting schema tables reference](https://docs.microsoft.com/en-US/microsoft-365/security/defender/advanced-hunting-schema-tables?view=o365-worldwide)

[MS 365 Defender/Azure Sentinel detections/custom KQL querries](https://github.com/Azure/Azure-Sentinel)

### Table Schema:
| Acronym | Product |
| :--- | :--- |
| **MS365D** | Microsoft 365 Defender
| **MDI** | Microsoft Defender for Identity
| **MDE** | Microsoft Defender for Endpoint
| **MDA** | Microsoft Defender for Cloud Apps
| **MDO** | Microsoft Defender for Office 365
| **TVM** | Microsoft Defender Vulnerability Management

Schema Overview
=================
  * MS365D - Alerts
    * [Table: AlertInfo](#table-alertinfo)
    * [Table: AlertEvidence](#table-alertevidence)
    * [Table: BehaviorInfo](#table-behaviorinfo)
    * [Table: BehaviorEntities](#table-behaviorentities)
  * MDA/MDI - Apps & identities
    * [Table: IdentityInfo](#table-identityinfo)
    * [Table: IdentityLogonEvents](#table-identitylogonevents)
    * [Table: IdentityQueryEvents](#table-identityqueryevents)
    * [Table: IdentityDirectoryEvents](#table-identitydirectoryevents)
    * [Table: CloudAppEvents](#table-cloudappevents)
    * [Table: AADSpnSignInEventsBeta](#table-aadspnsignineventsbeta)
    * [Table: AADSignInEventsBeta](#table-aadsignineventsbeta)
  * MDO - Email
    * [Table: EmailEvents](#table-emailevents)
    * [Table: EmailAttachmentInfo](#table-emailattachmentinfo)
    * [Table: EmailUrlInfo](#table-emailurlinfo)
    * [Table: EmailPostDeliveryEvents](#table-emailpostdeliveryevents)
    * [Table: UrlClickEvents](#table-urlclickevents)
  * MDE - Devices
    * [Table: DeviceInfo](#table-deviceinfo)
    * [Table: DeviceNetworkInfo](#table-devicenetworkinfo)
    * [Table: DeviceProcessEvents](#table-deviceprocessevents)
    * [Table: DeviceNetworkEvents](#table-devicenetworkevents)
    * [Table: DeviceFileEvents](#table-devicefileevents)
    * [Table: DeviceRegistryEvents](#table-deviceregistryevents)
    * [Table: DeviceLogonEvents](#table-devicelogonevents)
    * [Table: DeviceImageLoadEvents](#table-deviceimageloadevents)
    * [Table: DeviceEvents](#table-deviceevents)
    * [Table: DeviceFileCertificateInfo](#table-devicefilecertificateinfo)
* TVM - Threat & Vulnerability Management
    * [Table: DeviceTvmSoftwareVulnerabilities](#table-devicetvmsoftwarevulnerabilities)
    * [Table: DeviceTvmSoftwareVulnerabilitiesKB](#table-devicetvmsoftwarevulnerabilitieskb)
    * [Table: DeviceTvmSecureConfigurationAssessment](#table-devicetvmsecureconfigurationassessment)
    * [Table: DeviceTvmSecureConfigurationAssessmentKB](#table-devicetvmsecureconfigurationassessmentkb)
    * [Table: DeviceTvmSoftwareInventory](#table-devicetvmsoftwareinventory)
    * [Table: DeviceTvmInfoGathering](#table-devicetvminfogathering)
    * [Table: DeviceTvmInfoGatheringKB](#table-devicetvminfogatheringkb)
    * [Table: DeviceTvmSoftwareEvidenceBeta](#table-devicetvmsoftwareevidencebeta)
* TVM - Threat & Vulnerability Management add-on
    * [Table: DeviceBaselineComplianceAssessment](#table-devicebaselinecomplianceassessment)
    * [Table: DeviceBaselineComplianceAssessmentKB](#table-devicebaselinecomplianceassessmentkb)
    * [Table: DeviceBaselineComplianceProfiles](#table-devicebaselinecomplianceprofiles)
    * [Table: DeviceTvmCertificateInfo](#table-devicetvmcertificateinfo)
    * [Table: DeviceTvmBrowserExtensions](#table-devicetvmbrowserextensions)
    * [Table: DeviceTvmBrowserExtensionsKB](#table-devicetvmbrowserextensionskb)
    * [Table: DeviceTvmHardwareFirmware](#table-devicetvmhardwarefirmware)

## Table: AADSignInEventsBeta

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-aadsignineventsbeta-table?view=o365-worldwide)
**Description:** Information about Azure Active Directory (AAD) sign-in events either by a user (interactive) or a client on the user's behalf (non-interactive)

### Table Schema:
| Field | Description |
| --- | --- |
| **AadDeviceId** | Unique identifier for the device in Azure AD |
| **AccountDisplayName** | Name displayed in the address book entry for the account user. This is usually a combination of the given name, middle initial, and surname of the user. |
| **AccountObjectId** | Unique identifier for the account in Azure AD |
| **AccountUpn** | User principal name (UPN) of the account |
| **AlternateSignInName** | On-premises user principal name (UPN) of the user signing in to Azure AD |
| **Application** | Application that performed the recorded action |
| **ApplicationId** | Unique identifier for the application  |
| **AuthenticationProcessingDetails** | Details about the authentication processor |
| **AuthenticationRequirement** | Type of authentication required for the sign-in. Possible values: multiFactorAuthentication (MFA was required) and singleFactorAuthentication (no MFA was required). |
| **Browser** | Details about the version of the browser used to sign in |
| **City** | City where the client IP address is geolocated |
| **ClientAppUsed** | Indicates the client app used |
| **ConditionalAccessPolicies** | Details of the conditional access policies applied to the sign-in event |
| **ConditionalAccessStatus** | Status of the conditional access policies applied to the sign-in. Possible values are 0 (policies applied), 1 (attempt to apply policies failed), or 2 (policies not applied). |
| **CorrelationId** | Unique identifier of the sign-in event |
| **Country** | Country/Region where the account user is located |
| **DeviceName** | Fully qualified domain name (FQDN) of the device |
| **DeviceTrustType** | Indicates the trust type of the device that signed in. For managed device scenarios only. Possible values are Workplace, AzureAd, and ServerAd. |
| **EndpointCall** | Information about the AAD endpoint that the request was sent to and the type of request sent during sign in |
| **ErrorCode** | Contains the error code if a sign-in error occurs. To find a description of a specific error code, visit https://aka.ms/AADsigninsErrorCodes |
| **IPAddress** | IP address assigned to the device during communication |
| **IsCompliant** | Indicates whether the device that initiated the event is compliant or not |
| **IsExternalUser** | Indicates whether a user inside the network does not belong to the organizationâ€™s domain |
| **IsGuestUser** | Indicates whether the user that signed in is a guest in the tenant |
| **IsManaged** | Indicates whether the endpoint has been onboarded to and is managed by Microsoft Defender for Endpoint |
| **LastPasswordChangeTimestamp** | Date and time when the user that signed in last changed their password |
| **Latitude** | The north to south coordinates of the sign-in location |
| **LogonType** | Type of logon session, specifically interactive, remote interactive (RDP), network, batch, and service |
| **Longitude** | The east to west coordinates of the sign-in location |
| **NetworkLocationDetails** | Network location details of the authentication processor of the sign-in event |
| **OSPlatform** | Platform of the operating system running on the device. This indicates specific operating systems, including variations within the same family, such as Windows 10 and Windows 7 |
| **ReportId** | Unique identifier for the event |
| **RequestId** | Unique identifier of the request |
| **ResourceDisplayName** | Display name of the resource accessed. The display name can contain any character. |
| **ResourceId** | Unique identifier of the resource accessed |
| **ResourceTenantId** | Unique identifier of the tenant of the resource accessed |
| **RiskEventTypes** | Array of risk event types applicable to the event |
| **RiskLevelAggregated** | Aggregated risk level during sign-in. Possible values: 0 (aggregated risk level not set), 1 (none), 10 (low), 50 (medium), or 100 (high). |
| **RiskLevelDuringSignIn** | User risk level at sign-in |
| **RiskState** | Indicates risky user state. Possible values: 0 (none), 1 (confirmed safe), 2 (remediated), 3 (dismissed), 4 (at risk), or 5 (confirmed compromised). |
| **SessionId** | Unique number assigned to a user by a website's server for the duration of the visit or session |
| **State** | State where the sign-in occurred, if available |
| **Timestamp** | Date and time when the record was generated |
| **TokenIssuerType** | Indicates if the token issuer is Azure Active Directory (0) or Active Directory Federation Services (1) |
| **UserAgent** | User agent information from the web browser or other client application |

### Examples:

### Finds attempts to sign in to disabled accounts, listed by IP address
```
// Finds attempts to sign in to disabled accounts, listed by IP address
let timeRange = 14d;
AADSignInEventsBeta 
| where  Timestamp >= ago(timeRange)
| where ErrorCode == '50057'  // The user account is disabled.
| summarize StartTime = min(Timestamp), EndTime = max(Timestamp), numberAccountsTargeted = dcount(AccountObjectId),
numberApplicationsTargeted = dcount(ApplicationId), accountSet = make_set(AccountUpn), applicationSet=make_set(Application),
numberLoginAttempts = count() by IPAddress
| extend timestamp = StartTime, IPCustomEntity = IPAddress
| order by numberLoginAttempts desc
```

### Gets a list of users that signed in from multiple locations in the last 24 hours
```
// Users with multiple cities 
// Get list of users that signed in from multiple cities for the last day. 
AADSignInEventsBeta 
| where Timestamp > ago(1d)
| summarize CountPerCity = dcount(City), citySet = make_set(City) by AccountUpn 
| where CountPerCity > 1
| order by CountPerCity desc
```


## Table: AADSpnSignInEventsBeta

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-aadspnsignineventsbeta-table?view=o365-worldwide)
**Description:** Information about sign-in events initiated by Azure Active Directory (AAD) service principal or managed identities

### Table Schema:
| Field | Description |
| --- | --- |
| **Application** | Application that performed the recorded action |
| **ApplicationId** | Unique identifier for the application  |
| **City** | City where the client IP address is geolocated |
| **CorrelationId** | Unique identifier of the sign-in event |
| **Country** | Country/Region where the account user is located |
| **ErrorCode** | Contains the error code if a sign-in error occurs. To find a description of a specific error code, visit https://aka.ms/AADsigninsErrorCodes |
| **IPAddress** | IP address assigned to the device during communication |
| **IsManagedIdentity** | Indicates whether the sign-in was initiated by a managed identity |
| **Latitude** | The north to south coordinates of the sign-in location |
| **Longitude** | The east to west coordinates of the sign-in location |
| **ReportId** | Unique identifier for the event |
| **RequestId** | Unique identifier of the request |
| **ResourceDisplayName** | Display name of the resource accessed. The display name can contain any character. |
| **ResourceId** | Unique identifier of the resource accessed |
| **ResourceTenantId** | Unique identifier of the tenant of the resource accessed |
| **ServicePrincipalId** | Unique identifier of the service principal that initiated the sign-in |
| **ServicePrincipalName** | Name of the service principal that initiated the sign-in |
| **State** | State where the sign-in occurred, if available |
| **Timestamp** | Date and time when the record was generated |

### Examples:

### Gets list of service principals with no sign-ins in the last ten days
```
// Inactive Service Principals 
// Service principals that had no sign-ins for the last 10d. 
AADSpnSignInEventsBeta
| where Timestamp > ago(30d)
| where ErrorCode == 0
| summarize LastSignIn = max(Timestamp) by ServicePrincipalId
| where LastSignIn < ago(10d)
| order by LastSignIn desc
```

### Gets list of the top 100 most active managed identities in the last 24 hours
```
// Most active Managed Identities 
// Gets list of top 100 most active managed identities for the last day. 
AADSpnSignInEventsBeta
| where Timestamp > ago(1d)
| where IsManagedIdentity == True
| summarize CountPerManagedIdentity = count() by ServicePrincipalId
| order by CountPerManagedIdentity desc
| take 100
```


## Table: AlertEvidence

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-alertevidence-table?view=o365-worldwide)
**Description:** Files, IP addresses, URLs, users, or devices associated with alerts

### Table Schema:
| Field | Description |
| --- | --- |
| **AccountDomain** | Domain of the account |
| **AccountName** | User name of the account |
| **AccountObjectId** | Unique identifier for the account in Azure AD |
| **AccountSid** | Security Identifier (SID) of the account |
| **AccountUpn** | User principal name (UPN) of the account |
| **AdditionalFields** | Additional information about the entity or event |
| **AlertId** | Unique identifier for the alert |
| **Application** | Application that performed the recorded action |
| **ApplicationId** | Unique identifier for the application  |
| **AttackTechniques** | MITRE ATT&CK techniques associated with the activity that triggered the alert |
| **Categories** | List of categories that the information belongs to, in JSON array format |
| **DetectionSource** | Detection technology or sensor that identified the notable component or activity |
| **DeviceId** | Unique identifier for the device in the service |
| **DeviceName** | Fully qualified domain name (FQDN) of the device |
| **EmailSubject** | Subject of the email |
| **EntityType** | Type of object, such as a file, a process, a device, or a user |
| **EvidenceDirection** | Indicates whether the entity is the source or the destination of a network connection |
| **EvidenceRole** | How the entity is involved in an alert, indicating whether it is impacted or is merely related |
| **FileName** | Name of the file that the recorded action was applied to |
| **FileSize** | Size of the file in bytes |
| **FolderPath** | Folder containing the file that the recorded action was applied to |
| **LocalIP** | IP address assigned to the local machine used during communication |
| **NetworkMessageId** | Unique identifier for the email, generated by Office 365 |
| **OAuthApplicationId** | Unique identifier of the third-party OAuth application |
| **ProcessCommandLine** | Command line used to create the new process |
| **RegistryKey** | Registry key that the recorded action was applied to |
| **RegistryValueData** | Data of the registry value that the recorded action was applied to |
| **RegistryValueName** | Name of the registry value that the recorded action was applied to |
| **RemoteIP** | IP address that was being connected to |
| **RemoteUrl** | URL or fully qualified domain name (FQDN) that was being connected to |
| **ServiceSource** | Product or service that provided the alert information |
| **Severity** | Indicates the potential impact (high, medium, or low) of the threat indicator or breach activity identified by the alert |
| **SHA1** | SHA-1 hash of the file that the recorded action was applied to |
| **SHA256** | SHA-256 of the file that the recorded action was applied to |
| **ThreatFamily** | Malware family that the suspicious or malicious file or process has been classified under |
| **Timestamp** | Date and time when the record was generated |
| **Title** | Title of the alert |

### Examples:

### List all alerts involving a particular user account
```
let userID = "<inert your AAD user ID>";
let userSid = "<inert your user SID>";
AlertEvidence
| where EntityType == "User" and (AccountObjectId == userID or AccountSid == userSid )
| join AlertInfo on AlertId
| project Timestamp, AlertId, Title, Category , Severity , ServiceSource , DetectionSource , AttackTechniques, AccountObjectId, AccountName, AccountDomain , AccountSid 
```

### List all alerts involving a specific device
```
let myDevice = "<insert your device ID>";
let deviceName = "<insert your device name>";
AlertEvidence
| extend DeviceName = todynamic(AdditionalFields)["HostName"]
| where EntityType == "Machine" and (DeviceId == myDevice or DeviceName == deviceName)
| project DeviceId, DeviceName, AlertId 
| join AlertInfo on AlertId
| project Timestamp, AlertId, Title, Category , Severity , ServiceSource , DetectionSource , AttackTechniques, DeviceId, DeviceName
```


## Table: AlertInfo

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-alertinfo-table?view=o365-worldwide)
**Description:** Alerts from Microsoft Defender for Endpoint, Microsoft Defender for Office 365, Microsoft Cloud App Security, and Microsoft Defender for Identity, including severity information and threat categorization

### Table Schema:
| Field | Description |
| --- | --- |
| **AlertId** | Unique identifier for the alert |
| **AttackTechniques** | MITRE ATT&CK techniques associated with the activity that triggered the alert |
| **Category** | Type of threat indicator or breach activity identified by the alert |
| **DetectionSource** | Detection technology or sensor that identified the notable component or activity |
| **ServiceSource** | Product or service that provided the alert information |
| **Severity** | Indicates the potential impact (high, medium, or low) of the threat indicator or breach activity identified by the alert |
| **Timestamp** | Date and time when the record was generated |
| **Title** | Title of the alert |

### Examples:

### Get the number of alerts by MITRE ATT&CK technique
```
AlertInfo
| where isnotempty(AttackTechniques)
| mvexpand todynamic(AttackTechniques) to typeof(string)
| summarize AlertCount = dcount(AlertId) by AttackTechniques
| sort by AlertCount desc
```

### Get the number of alerts by severity
```
AlertInfo
| summarize alertsCount=dcount(AlertId) by Severity
| sort by alertsCount desc
```


## Table: BehaviorEntities

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-behaviorentities-table?view=o365-worldwide)
**Description:** Contains information about entities (file, process, device, user, and others) that are involved in a behavior

### Table Schema:
| Field | Description |
| --- | --- |
| **AccountDomain** | Domain of the account |
| **AccountName** | User name of the account |
| **AccountObjectId** | Unique identifier for the account in Azure AD |
| **AccountSid** | Security Identifier (SID) of the account |
| **AccountUpn** | User principal name (UPN) of the account |
| **ActionType** | Type of behavior |
| **AdditionalFields** | Additional information about the behavior |
| **Application** | Application that performed the recorded action |
| **ApplicationId** | Unique identifier for the application  |
| **BehaviorId** | Unique identifier for the behavior |
| **Categories** | Type of threat indicator or breach activity identified by the behavior |
| **DataSources** | Products or services that provided information for the behavior |
| **DetailedEntityRole** | The role of the entity in the behavior |
| **DetectionSource** | Detection technology or sensor that identified the notable component or activity |
| **DeviceId** | Unique identifier for the device in the service |
| **DeviceName** | Fully qualified domain name (FQDN) of the device |
| **EmailClusterId** | Identifier for the group of similar emails clustered based on heuristic analysis of their contents |
| **EmailSubject** | Subject of the email |
| **EntityRole** | Indicates whether the entity is impacted or merely related |
| **EntityType** | Type of object, such as a file, a process, a device, or a user |
| **FileName** | Name of the file that the recorded action was applied to |
| **FileSize** | Size of the file in bytes |
| **FolderPath** | Folder containing the file that the recorded action was applied to |
| **LocalIP** | IP address assigned to the local machine used during communication |
| **NetworkMessageId** | Unique identifier for the email, generated by Office 365 |
| **OAuthApplicationId** | Unique identifier of the third-party OAuth application |
| **ProcessCommandLine** | Command line used to create the new process |
| **RegistryKey** | Registry key that the recorded action was applied to |
| **RegistryValueData** | Data of the registry value that the recorded action was applied to |
| **RegistryValueName** | Name of the registry value that the recorded action was applied to |
| **RemoteIP** | IP address that was being connected to |
| **RemoteUrl** | URL or fully qualified domain name (FQDN) that was being connected to |
| **ServiceSource** | Product or service that identified the behavior |
| **SHA1** | SHA-1 hash of the file that the recorded action was applied to |
| **SHA256** | SHA-256 of the file that the recorded action was applied to |
| **ThreatFamily** | Malware family that the suspicious or malicious file or process has been classified under |
| **Timestamp** | Date and time when the record was generated |

## Table: BehaviorInfo

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-behaviorinfo-table?view=o365-worldwide)
**Description:** Contains information about behaviors, which in the context of Microsoft 365 Defender refers to a conclusion or insight based on one or more raw events, which can provide analysts more context in investigations

### Table Schema:
| Field | Description |
| --- | --- |
| **AccountObjectId** | Unique identifier for the account in Azure AD |
| **AccountUpn** | User principal name (UPN) of the account |
| **ActionType** | Type of behavior |
| **AdditionalFields** | Additional information about the behavior |
| **AttackTechniques** | MITRE ATT&CK techniques associated with the activity that triggered the behavior |
| **BehaviorId** | Unique identifier for the behavior |
| **Categories** | Type of threat indicator or breach activity identified by the behavior |
| **DataSources** | Products or services that provided information for the behavior |
| **Description** | Description of behavior |
| **DetectionSource** | Detection technology or sensor that identified the notable component or activity |
| **DeviceId** | Unique identifier for the device in the service |
| **EndTime** | Date and time of the last activity related to the behavior |
| **ServiceSource** | Product or service that identified the behavior |
| **StartTime** | Date and time of the first activity related to the behavior |
| **Timestamp** | Date and time when the record was generated |

### Examples:

### All behaviors in the last week on users that raised an alert in the last week
```
AlertEvidence
| where Timestamp > ago(7d)
| where EntityType == 'User' | distinct AccountObjectId
| join (BehaviorInfo | where Timestamp > ago(7d)) on AccountObjectId
```

### Get behaviors associated with a specific MITRE ATT&CK technique in the last week
```
let technique = 'Valid Accounts (T1078)';
BehaviorInfo
| where Timestamp > ago(7d)
| where AttackTechniques has technique
```


## Table: CloudAppEvents

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-cloudappevents-table?view=o365-worldwide)
**Description:** Events involving accounts and objects in Office 365 and other cloud apps and services

### Table Schema:
| Field | Description |
| --- | --- |
| **AccountDisplayName** | Name displayed in the address book entry for the account user. This is usually a combination of the given name, middle initial, and surname of the user. |
| **AccountId** | An identifier for the account as found by Microsoft Cloud App Security. Could be Azure Active Directory ID, user principal name, or other identifiers. |
| **AccountObjectId** | Unique identifier for the account in Azure AD |
| **AccountType** | Type of user account, indicating its general role and access levels, such as Regular, System, Admin, Application |
| **ActionType** | Type of activity that triggered the event |
| **ActivityObjects** | List of objects, such as files or folders, that were involved in the recorded activity |
| **ActivityType** | Type of activity that triggered the event |
| **AdditionalFields** | Additional information about the entity or event |
| **AppInstanceId** | Unique identifier for the instance of an application |
| **Application** | Application that performed the recorded action |
| **ApplicationId** | Unique identifier for the application  |
| **City** | City where the client IP address is geolocated |
| **CountryCode** | Two-letter code indicating the country where the client IP address is geolocated |
| **DeviceType** | Type of device based on purpose and functionality, such as network device, workstation, server, mobile, gaming console, or printer |
| **IPAddress** | IP address assigned to the device during communication |
| **IPCategory** | Additional information about the IP address |
| **IPTags** | Customer-defined information applied to specific IP addresses and IP address ranges |
| **IsAdminOperation** | Indicates whether the activity was performed by an administrator |
| **IsAnonymousProxy** | Indicates whether the IP address belongs to a known anonymous proxy |
| **IsExternalUser** | Indicates whether a user inside the network does not belong to the organizationâ€™s domain |
| **IsImpersonated** | Indicates whether the activity was performed by one user on behalf of another (impersonated) user |
| **ISP** | Internet service provider associated with  the IP address |
| **ObjectId** | Unique identifier of the object that the recorded action was applied to |
| **ObjectName** | Name of the object that the recorded action was applied to |
| **ObjectType** | The type of object, such as a file or a folder, that the recorded action was applied to |
| **OSPlatform** | Platform of the operating system running on the device. This indicates specific operating systems, including variations within the same family, such as Windows 10 and Windows 7 |
| **RawEventData** | Raw event information from the source application or service in JSON format |
| **ReportId** | Unique identifier for the event |
| **Timestamp** | Date and time when the record was generated |
| **UserAgent** | User agent information from the web browser or other client application |
| **UserAgentTags** | More information provided by Microsoft Cloud App Security in a tag in the user agent field. Can have any of the following values: Native client, Outdated browser, Outdated operating system, Robot |

### Examples:

### Find app activity renaming .docx files to .doc on devices
```
// Find applications that renamed .docx files to .doc on devices
CloudAppEvents 
| where Timestamp > ago(3d)
| where Application in ("Microsoft OneDrive for Business", "Microsoft SharePoint Online") and ActionType == "FileRenamed"
| extend NewFileNameExtension = tostring(RawEventData.DestinationFileExtension)
| extend OldFileNameExtension = tostring(RawEventData.SourceFileExtension)
| extend OldFileName = tostring(RawEventData.SourceFileName)
| extend NewFileName = tostring(RawEventData.DestinationFileName)
| where NewFileNameExtension == "doc" and OldFileNameExtension == "docx" 
| project RenameTime = Timestamp, OldFileNameExtension, OldFileName, NewFileNameExtension, NewFileName, ActionType, Application, AccountDisplayName, AccountObjectId
| join kind=inner (
DeviceFileEvents 
| where Timestamp > ago(3d)
| project FileName, AccountObjectId = InitiatingProcessAccountObjectId , DeviceName, SeenOnDevice = Timestamp, FolderPath 
) on $left.NewFileName == $right.FileName, AccountObjectId
| project RenameTime, NewFileName, OldFileName, Application, AccountObjectId, AccountDisplayName, DeviceName , SeenOnDevice, FolderPath
```

### Gives a list of sharing activities in cloud apps
```
// Gives a list of sharing activities in cloud apps
// Includes invitations, acceptances, requests and approvals for sharing files and folders in the cloud
CloudAppEvents
| where ActivityType == "Share"
| take 100
```


## Table: DeviceBaselineComplianceAssessment

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicebaselinecomplianceassessment-table?view=o365-worldwide)
**Description:** Baseline compliance assessment snapshot, indicating the status of various security configurations related to baseline profiles on devices

### Table Schema:
| Field | Description |
| --- | --- |
| **ConfigurationId** | Unique identifier for a specific configuration |
| **CurrentValue** | Set of detected values found on the device |
| **DeviceId** | Unique identifier for the device in the service |
| **DeviceName** | Fully qualified domain name (FQDN) of the device |
| **IsApplicable** | Indicates whether the configuration or policy is applicable |
| **IsCompliant** | Indicates whether the device that initiated the event is compliant or not |
| **IsExempt** | Indicates whether the device is exempt from having the baseline configuration |
| **OSPlatform** | Platform of the operating system running on the device. This indicates specific operating systems, including variations within the same family, such as Windows 10 and Windows 7 |
| **OSVersion** | Version of the operating system running on the machine |
| **ProfileId** | Unique identifier for the profile |
| **RecommendedValue** | Set of expected values for the current device setting to be complaint |
| **Source** | The registry path or other location used to determine the current device setting |

## Table: DeviceBaselineComplianceAssessmentKB

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicebaselinecomplianceassessmentkb-table?view=o365-worldwide)
**Description:** Knowledge base of various security configurations used by baseline compliance to assess devices

### Table Schema:
| Field | Description |
| --- | --- |
| **BenchmarkProfileLevels** | List of benchmark compliance levels for which the configuration is applicable |
| **CCEReference** | Unique Common Configuration Enumeration (CCE) identifier for the configuration |
| **ConfigurationBenchmark** | Industry benchmark recommending the configuration |
| **ConfigurationCategory** | Category or grouping to which the configuration belongs |
| **ConfigurationDescription** | Description of the configuration |
| **ConfigurationId** | Unique identifier for a specific configuration |
| **ConfigurationName** | Display name of the configuration |
| **ConfigurationRationale** | Description of any associated risks and rationale behind the configuration |
| **RecommendedValue** | Set of expected values for the current device setting to be complaint |
| **RemediationOptions** | Recommended actions to reduce or address any associated risks |
| **Source** | The registry path or other location used to determine the current device setting |

## Table: DeviceBaselineComplianceProfiles

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicebaselinecomplianceprofiles-table?view=o365-worldwide)
**Description:** Baseline profiles used for monitoring device baseline compliance

### Table Schema:
| Field | Description |
| --- | --- |
| **BaseBenchmark** | Industry benchmark on top of which the profile was created |
| **BenchmarkProfileLevel** | Benchmark compliance level set for the profile |
| **BenchmarkVersion** | Version of the industry benchmark on top of which the profile was created |
| **CreatedBy** | Identity of the user account who created the profile |
| **CreatedOn** | Date and time when the profile was created |
| **LastUpdatedBy** | Identity of the user account who last updated the profile |
| **LastUpdatedOn** | Date and time when the profile was last updated |
| **OSPlatform** | Platform of the operating system running on the device. This indicates specific operating systems, including variations within the same family, such as Windows 10 and Windows 7 |
| **OSVersion** | Version of the operating system running on the machine |
| **ProfileDescription** | Optional description providing additional information related to the profile |
| **ProfileId** | Unique identifier for the profile |
| **ProfileName** | Display name of the profile |
| **Status** | Indicator of the profile status - can be Enabled or Disabled |

## Table: DeviceEvents

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-deviceevents-table?view=o365-worldwide)
**Description:** Multiple event types, including events triggered by security controls such as Windows Defender Antivirus and exploit protection

### Table Schema:
| Field | Description |
| --- | --- |
| **AccountDomain** | Domain of the account |
| **AccountName** | User name of the account |
| **AccountSid** | Security Identifier (SID) of the account |
| **ActionType** | Type of activity that triggered the event |
| **AdditionalFields** | Additional information about the entity or event |
| **AppGuardContainerId** | Identifier for the virtualized container used by Application Guard to isolate browser activity |
| **DeviceId** | Unique identifier for the device in the service |
| **DeviceName** | Fully qualified domain name (FQDN) of the device |
| **FileName** | Name of the file that the recorded action was applied to |
| **FileOriginIP** | IP address where the file was downloaded from |
| **FileOriginUrl** | URL where the file was downloaded from |
| **FileSize** | Size of the file in bytes |
| **FolderPath** | Folder containing the file that the recorded action was applied to |
| **InitiatingProcessAccountDomain** | Domain of the account that ran the process responsible for the event |
| **InitiatingProcessAccountName** | User name of the account that ran the process responsible for the event |
| **InitiatingProcessAccountObjectId** | Azure AD object ID of the user account that ran the process responsible for the event |
| **InitiatingProcessAccountSid** | Security Identifier (SID) of the account that ran the process responsible for the event |
| **InitiatingProcessAccountUpn** | User principal name (UPN) of the account that ran the process responsible for the event |
| **InitiatingProcessCommandLine** | Command line used to run the process that initiated the event |
| **InitiatingProcessCreationTime** | Date and time when the process that initiated the event was started |
| **InitiatingProcessFileName** | Name of the process that initiated the event |
| **InitiatingProcessFileSize** | Size of the process (image file) that initiated the event |
| **InitiatingProcessFolderPath** | Folder containing the process (image file) that initiated the event |
| **InitiatingProcessId** | Process ID (PID) of the process that initiated the event |
| **InitiatingProcessLogonId** | Identifier for a logon session of the process that initiated the event. This identifier is unique on the same machine only between restarts. |
| **InitiatingProcessMD5** | MD5 hash of the process (image file) that initiated the event |
| **InitiatingProcessParentCreationTime** | Date and time when the parent of the process responsible for the event was started |
| **InitiatingProcessParentFileName** | Name of the parent process that spawned the process responsible for the event |
| **InitiatingProcessParentId** | Process ID (PID) of the parent process that spawned the process responsible for the event |
| **InitiatingProcessSHA1** | SHA-1 hash of the process (image file) that initiated the event |
| **InitiatingProcessSHA256** | SHA-256 hash of the process (image file) that initiated the event. This field is usually not populated - use the SHA1 column when available. |
| **InitiatingProcessVersionInfoCompanyName** | Company name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoFileDescription** | Description from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoInternalFileName** | Internal file name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoOriginalFileName** | Original file name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoProductName** | Product name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoProductVersion** | Product version from the version information of the process (image file) responsible for the event |
| **LocalIP** | IP address assigned to the local machine used during communication |
| **LocalPort** | TCP port on the local machine used during communication |
| **LogonId** | Identifier for a logon session. This identifier is unique on the same machine only between restarts |
| **MD5** | MD5 hash of the file that the recorded action was applied to |
| **ProcessCommandLine** | Command line used to create the new process |
| **ProcessCreationTime** | Date and time the process was created |
| **ProcessId** | Process ID (PID) of the newly created process |
| **ProcessTokenElevation** | Indicates the type of token elevation applied to the newly created process. Possible values: TokenElevationTypeLimited (restricted), TokenElevationTypeDefault (standard), and TokenElevationTypeFull (elevated) |
| **RegistryKey** | Registry key that the recorded action was applied to |
| **RegistryValueData** | Data of the registry value that the recorded action was applied to |
| **RegistryValueName** | Name of the registry value that the recorded action was applied to |
| **RemoteDeviceName** | Name of the device that performed a remote operation on the affected machine. Depending on the event being reported, this name could be a fully-qualified domain name (FQDN), a NetBIOS name, or a host name without domain information. |
| **RemoteIP** | IP address that was being connected to |
| **RemotePort** | TCP port on the remote device that was being connected to |
| **RemoteUrl** | URL or fully qualified domain name (FQDN) that was being connected to |
| **ReportId** | Event identifier based on a repeating counter.To identify unique events, this column must be used in conjunction with the DeviceName and Timestamp columns. |
| **SHA1** | SHA-1 hash of the file that the recorded action was applied to |
| **SHA256** | SHA-256 of the file that the recorded action was applied to |
| **Timestamp** | Date and time when the record was generated |

### ActionTypes:
| ActionType | Description |
| --- | --- |
| **AccountCheckedForBlankPassword** | An account was checked for a blank password. |
| **AntivirusDefinitionsUpdated** | Security intelligence updates for Windows Defender Antivirus were applied successfully. |
| **AntivirusDefinitionsUpdateFailed** | Security intelligence updates for Windows Defender Antivirus were not applied. |
| **AntivirusDetection** | Windows Defender Antivirus detected a threat. |
| **AntivirusEmergencyUpdatesInstalled** | Emergency security intelligence updates for Windows Defender Antivirus were applied. |
| **AntivirusError** | Windows Defender Antivirus encountered an error while taking action on malware or a potentially unwanted application. |
| **AntivirusMalwareActionFailed** | Windows Defender Antivirus attempted to take action on malware or a potentially unwanted application but the action failed. |
| **AntivirusMalwareBlocked** | Windows Defender Antivirus blocked files or activity involving malware potentially unwanted applications or suspicious behavior. |
| **AntivirusScanCancelled** | A Windows Defender Antivirus scan was cancelled. |
| **AntivirusScanCompleted** | A Windows Defender Antivirus scan completed successfully. |
| **AntivirusScanFailed** | A Windows Defender Antivirus scan did not complete successfully. |
| **AntivirusTroubleshootModeEvent** | The troubleshooting mode in Microsoft Defender Antivirus was used. |
| **AppControlAppInstallationAudited** | Application control detected the installation of an untrusted app. |
| **AppControlAppInstallationBlocked** | Application control blocked the installation of an untrusted app. |
| **AppControlCIScriptAudited** | A script or MSI file generated by Windows LockDown Policy was audited. |
| **AppControlCIScriptBlocked** | A script or MSI file generated by Windows LockDown Policy was blocked. |
| **AppControlCodeIntegrityDriverRevoked** | Application control found a driver with a revoked certificate. |
| **AppControlCodeIntegrityImageAudited** | Application control detected an executable file that violated code integrity policies. |
| **AppControlCodeIntegrityImageRevoked** | Application control found an executable file with a revoked certificate. |
| **AppControlCodeIntegrityOriginAllowed** | Application control allowed a file due to its good reputation (ISG) or installation source (managed installer). |
| **AppControlCodeIntegrityOriginAudited** | Application control would have blocked a file due to its bad reputation (ISG) or installation source (managed installer) if the policy was enforced. |
| **AppControlCodeIntegrityOriginBlocked** | Application control blocked a file due to its bad reputation (ISG) or installation source (managed installer). |
| **AppControlCodeIntegrityPolicyAudited** | Application control detected a code integrity policy violation. |
| **AppControlCodeIntegrityPolicyBlocked** | Application control blocked a code integrity policy violation. |
| **AppControlCodeIntegrityPolicyLoaded** | An application control code integrity policy was loaded. |
| **AppControlCodeIntegritySigningInformation** | Application control signing information was generated. |
| **AppControlExecutableAudited** | Application control detected the use of an untrusted executable. |
| **AppControlExecutableBlocked** | Application control blocked the use of an untrusted executable. |
| **AppControlPackagedAppAudited** | Application control detected the use of an untrusted packaged app. |
| **AppControlPackagedAppBlocked** | Application control blocked the installation of an untrusted packaged app. |
| **AppControlPolicyApplied** | An application control policy was applied to the device. |
| **AppControlScriptAudited** | Application control detected the use of an untrusted script. |
| **AppControlScriptBlocked** | Application control blocked the use of an untrusted script. |
| **AppGuardBrowseToUrl** | A URL was accessed from within an application guard container. |
| **AppGuardCreateContainer** | Application guard initiated an isolated container. |
| **AppGuardLaunchedWithUrl** | The opening of an untrusted URL has initiated an application guard container. |
| **AppGuardResumeContainer** | Application guard resumed an isolated container from a suspended state. |
| **AppGuardStopContainer** | Application guard stopped an isolated container. |
| **AppGuardSuspendContainer** | Application guard suspended an isolated container. |
| **AppLockerBlockExecutable** | AppLocker prevented an untrusted executable from running. |
| **AppLockerBlockPackagedApp** | AppLocker prevented an untrusted packaged app from running. |
| **AppLockerBlockPackagedAppInstallation** | AppLocker prevented the installation of an untrusted packaged app. |
| **AppLockerBlockScript** | AppLocker prevented an untrusted script from running. |
| **AsrAdobeReaderChildProcessAudited** | An attack surface reduction rule detected Adobe Reader creating a child process. |
| **AsrAdobeReaderChildProcessBlocked** | An attack surface reduction rule blocked Adobe Reader from creating a child process. |
| **AsrExecutableEmailContentAudited** | An attack surface reduction rule detected the launch of executable content from an email client and or webmail. |
| **AsrExecutableEmailContentBlocked** | An attack surface reduction rule blocked executable content from an email client and or webmail. |
| **AsrExecutableOfficeContentAudited** | An attack surface reduction rule detected an Office application creating executable content. |
| **AsrExecutableOfficeContentBlocked** | An attack surface reduction rule blocked an Office application from creating executable content. |
| **AsrLsassCredentialTheftAudited** | An attack surface reduction rule detected possible credential theft from lsass.exe. |
| **AsrLsassCredentialTheftBlocked** | An attack surface reduction rule blocked possible credential theft from lsass.exe. |
| **AsrObfuscatedScriptAudited** | An attack surface reduction rule detected the execution of scripts that appear obfuscated. |
| **AsrObfuscatedScriptBlocked** | An attack surface reduction rule blocked the execution of scripts that appear obfuscated. |
| **AsrOfficeChildProcessAudited** | An attack surface reduction rule detected an Office application spawning a child process. |
| **AsrOfficeChildProcessBlocked** | An attack surface reduction rule blocked an Office application from creating child processes. |
| **AsrOfficeCommAppChildProcessAudited** | An attack surface reduction rule detected an Office communication app attempting to spawn a child process. |
| **AsrOfficeCommAppChildProcessBlocked** | An attack surface reduction rule blocked an Office communication app from spawning a child process. |
| **AsrOfficeMacroWin32ApiCallsAudited** | An attack surface reduction rule detected Win32 API calls from Office macros. |
| **AsrOfficeMacroWin32ApiCallsBlocked** | An attack surface reduction rule blocked Win32 API calls from Office macros. |
| **AsrOfficeProcessInjectionAudited** | An attack surface reduction rule detected an Office application injecting code into other processes. |
| **AsrOfficeProcessInjectionBlocked** | An attack surface reduction rule blocked an Office application from injecting code into other processes. |
| **AsrPersistenceThroughWmiAudited** | An attack surface reduction rule detected an attempt to establish persistence through WMI event subscription. |
| **AsrPersistenceThroughWmiBlocked** | An attack surface reduction rule blocked an attempt to establish persistence through WMI event subscription. |
| **AsrPsexecWmiChildProcessAudited** | An attack surface reduction rule detected the use of PsExec or WMI commands to spawn a child process. |
| **AsrPsexecWmiChildProcessBlocked** | An attack surface reduction rule blocked the use of PsExec or WMI commands to spawn a child process. |
| **AsrRansomwareAudited** | An attack surface reduction rule detected ransomware activity. |
| **AsrRansomwareBlocked** | An attack surface reduction rule blocked ransomware activity. |
| **AsrScriptExecutableDownloadAudited** | An attack surface reduction rule detected JavaScript or VBScript code launching downloaded executable content. |
| **AsrScriptExecutableDownloadBlocked** | An attack surface reduction rule blocked JavaScript or VBScript code from launching downloaded executable content. |
| **AsrUntrustedExecutableAudited** | An attack surface reduction rule detected the execution of an untrusted file that doesn't meet criteria for age or prevalence. |
| **AsrUntrustedExecutableBlocked** | An attack surface reduction rule blocked the execution of an untrusted file that doesn't meet criteria for age or prevalence. |
| **AsrUntrustedUsbProcessAudited** | An attack surface reduction rule detected the execution of an untrusted and unsigned processes from a USB device. |
| **AsrUntrustedUsbProcessBlocked** | An attack surface reduction rule blocked the execution of an untrusted and unsigned processes from a USB device. |
| **AsrVulnerableSignedDriverAudited** | An attack surface reduction rule detected a signed driver that has known vulnerabilities. |
| **AsrVulnerableSignedDriverBlocked** | An attack surface reduction rule blocked a signed driver that has known vulnerabilities. |
| **AuditPolicyModification** | Changes in the Windows audit policy (which feed events to the event log). |
| **BitLockerAuditCompleted** | An audit for BitLocker encryption was completed. |
| **BluetoothPolicyTriggered** | A Bluetooth service activity was allowed or blocked by a device control policy. |
| **BrowserLaunchedToOpenUrl** | A web browser opened a URL that originated as a link in another application. |
| **ControlFlowGuardViolation** | Control Flow Guard terminated an application after detecting an invalid function call |
| **ControlledFolderAccessViolationAudited** | Controlled folder access detected an attempt to modify a protected folder. |
| **ControlledFolderAccessViolationBlocked** | Controlled folder access blocked an attempt to modify a protected folder. |
| **CreateRemoteThreadApiCall** | A thread that runs in the virtual address space of another process was created. |
| **CredentialsBackup** | The backup feature in Credential Manager was initiated |
| **DeviceBootAttestationInfo** | System Guard generated a boot-time attestation report. |
| **DirectoryServiceObjectCreated** | An object was added to the directory service. |
| **DirectoryServiceObjectModified** | An object in the directory service was modified. |
| **DlpPocPrintJob** | A file was sent to a printer device for printing. |
| **DnsQueryRequest** | A DNS request was initiated. |
| **DnsQueryResponse** | A response to a DNS query was sent. |
| **DpapiAccessed** | Decription of saved sensitive data encrypted using DPAPI. |
| **DriverLoad** | A driver was loaded. |
| **ExploitGuardAcgAudited** | Arbitrary code guard (ACG) in exploit protection detected an attempt to modify code page permissions or create unsigned code pages. |
| **ExploitGuardAcgEnforced** | Arbitrary code guard (ACG) blocked an attempt to modify code page permissions or create unsigned code pages. |
| **ExploitGuardChildProcessAudited** | Exploit protection detected the creation of a child process. |
| **ExploitGuardChildProcessBlocked** | Exploit protection blocked the creation of a child process. |
| **ExploitGuardEafViolationAudited** | Export address filtering (EAF) in exploit protection detected possible exploitation activity. |
| **ExploitGuardEafViolationBlocked** | Export address filtering (EAF) in exploit protection blocked possible exploitation activity. |
| **ExploitGuardIafViolationAudited** | Import address filtering (IAF) in exploit protection detected possible exploitation activity. |
| **ExploitGuardIafViolationBlocked** | Import address filtering (IAF) in exploit protection blocked possible exploitation activity. |
| **ExploitGuardLowIntegrityImageAudited** | Exploit protection detected the launch of a process from a low-integrity file. |
| **ExploitGuardLowIntegrityImageBlocked** | Exploit protection blocked the launch of a process from a low-integrity file. |
| **ExploitGuardNetworkProtectionAudited** | Network protection detected an attempt to access a malicious or unwanted IP address domain or URL. |
| **ExploitGuardNetworkProtectionBlocked** | Network protection blocked a malicious or unwanted IP address domain or URL. |
| **ExploitGuardNonMicrosoftSignedAudited** | Exploit protection detected the launch of a process from an image file that is not signed by Microsoft. |
| **ExploitGuardNonMicrosoftSignedBlocked** | Exploit protection blocked the launch of a process from an image file that is not signed by Microsoft. |
| **ExploitGuardRopExploitAudited** | Exploit protection detected possible return-object programming (ROP) exploitation. |
| **ExploitGuardRopExploitBlocked** | Exploit protection blocked possible return-object programming (ROP) exploitation. |
| **ExploitGuardSharedBinaryAudited** | Exploit protection detected the launch of a process from a remote shared file. |
| **ExploitGuardSharedBinaryBlocked** | Exploit protection blocked the launch of a process from a file in a remote device. |
| **ExploitGuardWin32SystemCallAudited** | Exploit protection detected a call to the Windows system API. |
| **ExploitGuardWin32SystemCallBlocked** | Exploit protection blocked a call to the Windows system API. |
| **FileTimestampModificationEvent** | File timestamp information was modified. |
| **FirewallInboundConnectionBlocked** | A firewall or another application blocked an inbound connection using the Windows Filtering Platform. |
| **FirewallInboundConnectionToAppBlocked** | The firewall blocked an inbound connection to an app. |
| **FirewallOutboundConnectionBlocked** | A firewall or another application blocked an outbound connection using the Windows Filtering Platform. |
| **FirewallServiceStopped** | The firewall service was stopped. |
| **GetAsyncKeyStateApiCall** | The GetAsyncKeyState function was called. This function can be used to obtain the states of input keys and buttons. |
| **GetClipboardData** | The GetClipboardData function was called. This function can be used obtain the contents of the system clipboard. |
| **LdapSearch** | An LDAP search was performed. |
| **LogonRightsSettingEnabled** | Interactive logon rights on the machine were granted to a user. |
| **MemoryRemoteProtect** | A process has modified the protection mask for a memory region used by another process. This might allow execution of content from non-executable memory. |
| **NamedPipeEvent** | A named pipe was created or opened. |
| **NetworkProtectionUserBypassEvent** | A user has bypassed network protection and accessed a blocked IP address, domain, or URL. |
| **NetworkShareObjectAccessChecked** | A request was made to access a file or folder shared on the network and permissions to the share was evaluated. |
| **NetworkShareObjectAdded** | A file or folder was shared on the network. |
| **NetworkShareObjectDeleted** | A file or folder shared on the network was deleted. |
| **NetworkShareObjectModified** | A file or folder shared on the network was modified. |
| **NtAllocateVirtualMemoryApiCall** | Memory was allocated for a process. |
| **NtAllocateVirtualMemoryRemoteApiCall** | Memory was allocated for a process remotely. |
| **NtMapViewOfSectionRemoteApiCall** | A section of a process's memory was mapped by calling the function NtMapViewOfSection. |
| **NtProtectVirtualMemoryApiCall** | The protection attributes for allocated memory was modified. |
| **OpenProcessApiCall** | The OpenProcess function was called indicating an attempt to open a handle to a local process and potentially manipulate that process. |
| **PasswordChangeAttempt** | An attempt to change a user password was made. |
| **PlistPropertyModified** | A property in the plist was modified. |
| **PnpDeviceAllowed** | Device control allowed a trusted plug and play (PnP) device. |
| **PnpDeviceBlocked** | Device control blocked an untrusted plug and play (PnP) device. |
| **PnpDeviceConnected** | A plug and play (PnP) device was attached. |
| **PowerShellCommand** | A PowerShell alias function filter cmdlet external script application script workflow or configuration was executed from a PowerShell host process. |
| **PrintJobBlocked** | Device control prevented an untrusted printer from printing. |
| **ProcessCreatedUsingWmiQuery** | A process was created using Windows Management Instrumentation (WMI). |
| **ProcessPrimaryTokenModified** | A process's primary token was modified. |
| **PTraceDetected** | A process trace (ptrace) was found to have occurred on this device. |
| **QueueUserApcRemoteApiCall** | An asynchronous procedure call (APC) was scheduled to execute in a user-mode thread. |
| **ReadProcessMemoryApiCall** | The ReadProcessMemory function was called indicating that a process read data from the process memory of another process. |
| **RemoteDesktopConnection** | A Remote Desktop connection was established |
| **RemoteWmiOperation** | A Windows Management Instrumentation (WMI) operation was initiated from a remote device. |
| **RemovableStorageFileEvent** | Removable storage file activity matched a device control removable storage access control policy. |
| **RemovableStoragePolicyTriggered** | Device control detected an attempted read/write/execute event from a removable storage device. |
| **SafeDocFileScan** | A document was sent to the cloud for analysis while in protected view. |
| **ScheduledTaskCreated** | A scheduled task was created. |
| **ScheduledTaskDeleted** | A scheduled task was deleted. |
| **ScheduledTaskDisabled** | A scheduled task was turned off. |
| **ScheduledTaskEnabled** | A scheduled task was turned on. |
| **ScheduledTaskUpdated** | A scheduled task was updated. |
| **ScreenshotTaken** | A screenshot was taken. |
| **SecurityGroupCreated** | A security group was created |
| **SecurityGroupDeleted** | A security group was deleted. |
| **SecurityLogCleared** | The security log was cleared. |
| **SensitiveFileRead** | A file that matched DLP policy was accessed or processes that are reading sensitive files such as ssh keys, Outlook mail archives etc. |
| **ServiceInstalled** | A service was installed. This is based on Windows event ID 4697, which requires the advanced security audit setting Audit Security System Extension. |
| **SetThreadContextRemoteApiCall** | The context of a thread was set from a user-mode process. |
| **ShellLinkCreateFileEvent** | A specially crafted link file (.lnk) was generated. The link file contains unusual attributes that might launch malicious code along with a legitimate file or application. |
| **SmartScreenAppWarning** | SmartScreen warned about running a downloaded application that is untrusted or malicious. |
| **SmartScreenExploitWarning** | SmartScreen warned about opening a web page that contains an exploit. |
| **SmartScreenUrlWarning** | SmartScreen warned about opening a low-reputation URL that might be hosting malware or is a phishing site. |
| **SmartScreenUserOverride** | A user has overridden a SmartScreen warning and continued to open an untrusted app or a low-reputation URL. |
| **TamperingAttempt** | An attempt to change Microsoft Defender 365 settings was made. |
| **UntrustedWifiConnection** | A connection was established to an open Wi-Fi access point that is set to connect automatically. |
| **UsbDriveDriveLetterChanged** | The drive letter assigned to a mounted USB storage device was modified |
| **UsbDriveMount** | A USB storage device was mounted as a drive. |
| **UsbDriveMounted** | A USB storage device was mounted as a drive. |
| **UsbDriveUnmount** | A USB storage device was unmounted. |
| **UsbDriveUnmounted** | A USB storage device was unmounted. |
| **UserAccountAddedToLocalGroup** | A user was added to a security-enabled local group. |
| **UserAccountCreated** | A local SAM account or a domain account was created. |
| **UserAccountDeleted** | A user account was deleted. |
| **UserAccountModified** | A user account was modified. |
| **UserAccountRemovedFromLocalGroup** | A user was removed from a security-enabled local group. |
| **WmiBindEventFilterToConsumer** | A filter for WMI events was bound to a consumer. This enables listening for all kinds of system events and triggering corresponding actions, including potentially malicious ones. |
| **WriteProcessMemoryApiCall** | The WriteProcessMemory function was called indicating that a process has written data into memory for another process. |
| **WriteToLsassProcessMemory** | The WriteProcessMemory function was called indicating that a process has written data into memory for another process. |

### Examples:

### Get antivirus scan events, including completed and cancelled scans on a device in the past week
```
// Get antivirus scan events, including completed and cancelled scans
let myDevice = "<insert your device ID>";
DeviceEvents 
| where ActionType startswith "AntivirusScan"  and Timestamp > ago(7d) and DeviceId == myDevice
| extend ScanDesc = parse_json(AdditionalFields)
|project Timestamp, DeviceName, ActionType, Domain = ScanDesc.Domain, ScanId= ScanDesc.ScanId, User = ScanDesc.User, ScanParametersIndex = ScanDesc.ScanParametersIndex, ScanTypeIndex = ScanDesc.ScanTypeIndex
```

### Get the list the USB devices attached to a device in the past week
```
//Get the list the USB devices attached to a device in the past week
let myDevice = "<insert your device ID>";
DeviceEvents 
| where ActionType == "UsbDriveMount" and Timestamp > ago(7d) and DeviceId == myDevice
| extend ProductName = todynamic(AdditionalFields)["ProductName"], SerialNumber = todynamic(AdditionalFields)["SerialNumber"], 
Manufacturer = todynamic(AdditionalFields)["Manufacturer"], Volume = todynamic(AdditionalFields)["Volume"]
| summarize lastInsert = max(Timestamp) by tostring(ProductName), tostring(SerialNumber), tostring(Manufacturer), tostring(Volume) 
```


## Table: DeviceFileCertificateInfo

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicefilecertificateinfo-table?view=o365-worldwide)
**Description:** Certificate information of signed files obtained from certificate verification events on endpoints

### Table Schema:
| Field | Description |
| --- | --- |
| **CertificateCountersignatureTime** | Date and time the certificate was countersigned |
| **CertificateCreationTime** | Date and time the certificate was created |
| **CertificateExpirationTime** | Date and time the certificate is set to expire |
| **CertificateSerialNumber** | Identifier for the certificate that is unique to the issuing certificate authority (CA) |
| **CrlDistributionPointUrls** | JSON array listing the URLs of network shares that contain certificates and certificate revocation lists (CRLs) |
| **DeviceId** | Unique identifier for the device in the service |
| **DeviceName** | Fully qualified domain name (FQDN) of the device |
| **IsRootSignerMicrosoft** | Indicates whether the signer of the root certificate is Microsoft |
| **IsSigned** | Indicates whether the file is signed |
| **Issuer** | Information about the issuing certificate authority (CA) |
| **IssuerHash** | Unique hash value identifying issuing certificate authority (CA) |
| **IsTrusted** | Indicates whether the file is trusted based on the results of the WinVerifyTrust function, which checks for unknown root certificate information, invalid signatures, revoked certificates, and other questionable attributes |
| **ReportId** | Event identifier based on a repeating counter.To identify unique events, this column must be used in conjunction with the DeviceName and Timestamp columns. |
| **SHA1** | SHA-1 hash of the file that the recorded action was applied to |
| **SignatureType** | Indicates whether signature information was read as embedded content in the file itself or read from an external catalog file |
| **Signer** | Information about the signer of the file |
| **SignerHash** | Unique hash value identifying the signer |
| **Timestamp** | Date and time when the record was generated |

### Examples:

### Find files with Elliptic Curve Cryptography (ECC) certificates showing Microsoft as the root signer but the incorrect signer name
```
DeviceFileCertificateInfo
| where Timestamp > ago(30d)
| where IsSigned == 1 
    and IsTrusted == 1 
    and IsRootSignerMicrosoft == 1
| where SignatureType == "Embedded"
| where Issuer !startswith "Microsoft" 
    and Issuer !startswith "Windows"
| project Timestamp, DeviceName,SHA1,Issuer,IssuerHash,Signer,SignerHash,
    CertificateCreationTime,CertificateExpirationTime,CrlDistributionPointUrls
| limit 10 
```


## Table: DeviceFileEvents

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicefileevents-table?view=o365-worldwide)
**Description:** File creation, modification, and other file system events

### Table Schema:
| Field | Description |
| --- | --- |
| **ActionType** | Type of activity that triggered the event |
| **AdditionalFields** | Additional information about the entity or event |
| **AppGuardContainerId** | Identifier for the virtualized container used by Application Guard to isolate browser activity |
| **DeviceId** | Unique identifier for the device in the service |
| **DeviceName** | Fully qualified domain name (FQDN) of the device |
| **FileName** | Name of the file that the recorded action was applied to |
| **FileOriginIP** | IP address where the file was downloaded from |
| **FileOriginReferrerUrl** | URL of the web page that links to the downloaded file |
| **FileOriginUrl** | URL where the file was downloaded from |
| **FileSize** | Size of the file in bytes |
| **FolderPath** | Folder containing the file that the recorded action was applied to |
| **InitiatingProcessAccountDomain** | Domain of the account that ran the process responsible for the event |
| **InitiatingProcessAccountName** | User name of the account that ran the process responsible for the event |
| **InitiatingProcessAccountObjectId** | Azure AD object ID of the user account that ran the process responsible for the event |
| **InitiatingProcessAccountSid** | Security Identifier (SID) of the account that ran the process responsible for the event |
| **InitiatingProcessAccountUpn** | User principal name (UPN) of the account that ran the process responsible for the event |
| **InitiatingProcessCommandLine** | Command line used to run the process that initiated the event |
| **InitiatingProcessCreationTime** | Date and time when the process that initiated the event was started |
| **InitiatingProcessFileName** | Name of the process that initiated the event |
| **InitiatingProcessFileSize** | Size of the process (image file) that initiated the event |
| **InitiatingProcessFolderPath** | Folder containing the process (image file) that initiated the event |
| **InitiatingProcessId** | Process ID (PID) of the process that initiated the event |
| **InitiatingProcessIntegrityLevel** | Integrity level of the process that initiated the event. Windows assigns integrity levels to processes based on certain characteristics, such as if they were launched from an internet download. These integrity levels influence permissions to resources. |
| **InitiatingProcessMD5** | MD5 hash of the process (image file) that initiated the event |
| **InitiatingProcessParentCreationTime** | Date and time when the parent of the process responsible for the event was started |
| **InitiatingProcessParentFileName** | Name of the parent process that spawned the process responsible for the event |
| **InitiatingProcessParentId** | Process ID (PID) of the parent process that spawned the process responsible for the event |
| **InitiatingProcessSHA1** | SHA-1 hash of the process (image file) that initiated the event |
| **InitiatingProcessSHA256** | SHA-256 hash of the process (image file) that initiated the event. This field is usually not populated - use the SHA1 column when available. |
| **InitiatingProcessTokenElevation** | Token type indicating the presence or absence of User Access Control (UAC) privilege elevation applied to the process that initiated the event |
| **InitiatingProcessVersionInfoCompanyName** | Company name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoFileDescription** | Description from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoInternalFileName** | Internal file name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoOriginalFileName** | Original file name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoProductName** | Product name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoProductVersion** | Product version from the version information of the process (image file) responsible for the event |
| **IsAzureInfoProtectionApplied** | Indicates whether the file is encrypted by Azure Information Protection |
| **MD5** | MD5 hash of the file that the recorded action was applied to |
| **PreviousFileName** | Original name of the file that was renamed as a result of the action |
| **PreviousFolderPath** | Original folder containing the file before the recorded action was applied |
| **ReportId** | Event identifier based on a repeating counter.To identify unique events, this column must be used in conjunction with the DeviceName and Timestamp columns. |
| **RequestAccountDomain** | Domain of the account used to remotely initiate the activity |
| **RequestAccountName** | User name of account used to remotely initiate the activity |
| **RequestAccountSid** | Security Identifier (SID) of the account used to remotely initiate the activity |
| **RequestProtocol** | Network protocol, if applicable, used to initiate the activity: Unknown, Local, SMB, or NFS |
| **RequestSourceIP** | IPv4 or IPv6 address of the remote device that initiated the activity |
| **RequestSourcePort** | Source port on the remote device that initiated the activity |
| **SensitivityLabel** | Label applied to an email, file, or other content to classify it for information protection |
| **SensitivitySubLabel** | Sublabel applied to an email, file, or other content to classify it for information protection; sensitivity sublabels are grouped under sensitivity labels but are treated independently |
| **SHA1** | SHA-1 hash of the file that the recorded action was applied to |
| **SHA256** | SHA-256 of the file that the recorded action was applied to |
| **ShareName** | Name of shared folder containing the file |
| **Timestamp** | Date and time when the record was generated |

### ActionTypes:
| ActionType | Description |
| --- | --- |
| **FileCreated** | A file was created on the device. |
| **FileDeleted** | A file was deleted. |
| **FileModified** | A file on the device was modified. |
| **FileRenamed** | A file on the device was renamed. |

### Examples:

### Get the list of sensitive files that were uploaded to a cloud app or service
```
//Get the list of sensitive files that were uploaded to a cloud app or service
DeviceFileEvents
| where SensitivityLabel in ("Highly Confidential", "Confidential") and Timestamp > ago(1d)
| project FileName, FolderPath, DeviceId, DeviceName , ActionType , SensitivityLabel , Timestamp 
| summarize LastTimeSeenOnDevice = max(Timestamp) by FileName, FolderPath, DeviceName , DeviceId , SensitivityLabel 
| join (CloudAppEvents
| where ActionType == "FileUploaded" and Timestamp > ago(1d) | extend FileName = tostring(RawEventData.SourceFileName) ) on FileName
| project UploadTime = Timestamp, ActionType, Application, FileName, SensitivityLabel, AccountDisplayName , 
AccountObjectId , IPAddress, CountryCode , LastTimeSeenOnDevice, DeviceName, DeviceId, FolderPath
| limit 100
```

### Track when a specific file has been copied or moved 
```
let myFile = '<file SHA1>';
DeviceFileEvents
| where SHA1 == myFile and ActionType == 'FileCreated'
| limit 100
```


## Table: DeviceImageLoadEvents

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-deviceimageloadevents-table?view=o365-worldwide)
**Description:** DLL loading events

### Table Schema:
| Field | Description |
| --- | --- |
| **ActionType** | Type of activity that triggered the event |
| **AppGuardContainerId** | Identifier for the virtualized container used by Application Guard to isolate browser activity |
| **DeviceId** | Unique identifier for the device in the service |
| **DeviceName** | Fully qualified domain name (FQDN) of the device |
| **FileName** | Name of the file that the recorded action was applied to |
| **FileSize** | Size of the file in bytes |
| **FolderPath** | Folder containing the file that the recorded action was applied to |
| **InitiatingProcessAccountDomain** | Domain of the account that ran the process responsible for the event |
| **InitiatingProcessAccountName** | User name of the account that ran the process responsible for the event |
| **InitiatingProcessAccountObjectId** | Azure AD object ID of the user account that ran the process responsible for the event |
| **InitiatingProcessAccountSid** | Security Identifier (SID) of the account that ran the process responsible for the event |
| **InitiatingProcessAccountUpn** | User principal name (UPN) of the account that ran the process responsible for the event |
| **InitiatingProcessCommandLine** | Command line used to run the process that initiated the event |
| **InitiatingProcessCreationTime** | Date and time when the process that initiated the event was started |
| **InitiatingProcessFileName** | Name of the process that initiated the event |
| **InitiatingProcessFileSize** | Size of the process (image file) that initiated the event |
| **InitiatingProcessFolderPath** | Folder containing the process (image file) that initiated the event |
| **InitiatingProcessId** | Process ID (PID) of the process that initiated the event |
| **InitiatingProcessIntegrityLevel** | Integrity level of the process that initiated the event. Windows assigns integrity levels to processes based on certain characteristics, such as if they were launched from an internet download. These integrity levels influence permissions to resources. |
| **InitiatingProcessMD5** | MD5 hash of the process (image file) that initiated the event |
| **InitiatingProcessParentCreationTime** | Date and time when the parent of the process responsible for the event was started |
| **InitiatingProcessParentFileName** | Name of the parent process that spawned the process responsible for the event |
| **InitiatingProcessParentId** | Process ID (PID) of the parent process that spawned the process responsible for the event |
| **InitiatingProcessSHA1** | SHA-1 hash of the process (image file) that initiated the event |
| **InitiatingProcessSHA256** | SHA-256 hash of the process (image file) that initiated the event. This field is usually not populated - use the SHA1 column when available. |
| **InitiatingProcessTokenElevation** | Token type indicating the presence or absence of User Access Control (UAC) privilege elevation applied to the process that initiated the event |
| **InitiatingProcessVersionInfoCompanyName** | Company name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoFileDescription** | Description from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoInternalFileName** | Internal file name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoOriginalFileName** | Original file name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoProductName** | Product name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoProductVersion** | Product version from the version information of the process (image file) responsible for the event |
| **MD5** | MD5 hash of the file that the recorded action was applied to |
| **ReportId** | Event identifier based on a repeating counter.To identify unique events, this column must be used in conjunction with the DeviceName and Timestamp columns. |
| **SHA1** | SHA-1 hash of the file that the recorded action was applied to |
| **SHA256** | SHA-256 of the file that the recorded action was applied to |
| **Timestamp** | Date and time when the record was generated |

### ActionTypes:
| ActionType | Description |
| --- | --- |
| **ImageLoaded** | A dynamic link library (DLL) was loaded. |

## Table: DeviceInfo

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-deviceinfo-table?view=o365-worldwide)
**Description:** Machine information, including OS information

### Table Schema:
| Field | Description |
| --- | --- |
| **AadDeviceId** | Unique identifier for the device in Azure AD |
| **AdditionalFields** | Additional information about the entity or event |
| **AssetValue** | Priority or value assigned to the device in relation to its importance in computing the organization's exposure score; can be: Low, Normal (Default), High |
| **ClientVersion** | Version of the endpoint agent or sensor running on the machine |
| **DeviceCategory** | Broader classification that groups certain device types under the following categories: Endpoint, Network device, IoT, Unknown |
| **DeviceId** | Unique identifier for the device in the service |
| **DeviceName** | Fully qualified domain name (FQDN) of the device |
| **DeviceSubtype** | Additional modifier for certain types of devices; for example, a mobile device can be a tablet or a smartphone; only available if device discovery finds enough information about this attribute |
| **DeviceType** | Type of device based on purpose and functionality, such as network device, workstation, server, mobile, gaming console, or printer |
| **ExclusionReason** | The reason for the device being excluded |
| **ExposureLevel** | The device's level of vulnerability to exploitation based on its exposure score; can be: Low, Medium, High |
| **IsAzureADJoined** | Boolean indicator of whether machine is joined to the Azure Active Directory |
| **IsExcluded** | Determines if the device is excluded from different views and reports in the portal |
| **IsInternetFacing** | Indicates whether the device is internet-facing |
| **JoinType** | The device's Azure Active Directory join type |
| **LoggedOnUsers** | List of all users that are logged on the machine at the time of the event in JSON array format |
| **MachineGroup** | Machine group of the machine. This group is used by role-based access control to determine access to the machine |
| **MergedDeviceIds** | Previous device IDs that have been assigned to the same device. |
| **MergedToDeviceId** | The most recent device ID assigned to a device  |
| **Model** | Model name or number of the product from the vendor or manufacturer; only available if device discovery finds enough information about this attribute |
| **OnboardingStatus** | Indicates whether the device is currently onboarded or not to Microsoft Defender For Endpoint or if the device is not supported |
| **OSArchitecture** | Architecture of the operating system running on the machine |
| **OSBuild** | Build version of the operating system running on the machine |
| **OSDistribution** | Distribution of the OS platform, such as Ubuntu or RedHat for Linux platforms |
| **OSPlatform** | Platform of the operating system running on the device. This indicates specific operating systems, including variations within the same family, such as Windows 10 and Windows 7 |
| **OSVersion** | Version of the operating system running on the machine |
| **OSVersionInfo** | Additional information about the OS version, such as the popular name, code name, or version number |
| **PublicIP** | Public IP address used by the onboarded machine to connect to the Windows Defender ATP service. This could be the IP address of the machine itself, a NAT device, or a proxy |
| **RegistryDeviceTag** | Device tag added through the registry |
| **ReportId** | Event identifier based on a repeating counter.To identify unique events, this column must be used in conjunction with the DeviceName and Timestamp columns. |
| **SensorHealthState** | Indicates health of the deviceâ€™s EDR sensor, if onboarded to Microsoft Defender For Endpoint |
| **Timestamp** | Date and time when the record was generated |
| **Vendor** | Name of the product vendor or manufacturer; only available if device discovery finds enough information about this attribute |

### Examples:

### List devices running operating systems older than Windows 10
```
//List devices running operating systems older than Windows 10
DeviceInfo 
| where todecimal(OSVersion) < 10 
| summarize by DeviceId, DeviceName, OSVersion, OSPlatform, OSBuild  
```

### List users that have logged on to a specific device during a specific time period
```
let myDevice = "<insert your device ID>";
DeviceInfo
| where Timestamp between (datetime(2020-05-19) .. datetime(2020-05-20)) and DeviceId == myDevice
| project LoggedOnUsers 
| mvexpand todynamic(LoggedOnUsers) to typeof(string)
| summarize by LoggedOnUsers
```


## Table: DeviceLogonEvents

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicelogonevents-table?view=o365-worldwide)
**Description:** 	Sign-ins and other authentication events

### Table Schema:
| Field | Description |
| --- | --- |
| **AccountDomain** | Domain of the account |
| **AccountName** | User name of the account |
| **AccountSid** | Security Identifier (SID) of the account |
| **ActionType** | Type of activity that triggered the event |
| **AdditionalFields** | Additional information about the entity or event |
| **AppGuardContainerId** | Identifier for the virtualized container used by Application Guard to isolate browser activity |
| **DeviceId** | Unique identifier for the device in the service |
| **DeviceName** | Fully qualified domain name (FQDN) of the device |
| **FailureReason** | Information explaining why the recorded action failed |
| **InitiatingProcessAccountDomain** | Domain of the account that ran the process responsible for the event |
| **InitiatingProcessAccountName** | User name of the account that ran the process responsible for the event |
| **InitiatingProcessAccountObjectId** | Azure AD object ID of the user account that ran the process responsible for the event |
| **InitiatingProcessAccountSid** | Security Identifier (SID) of the account that ran the process responsible for the event |
| **InitiatingProcessAccountUpn** | User principal name (UPN) of the account that ran the process responsible for the event |
| **InitiatingProcessCommandLine** | Command line used to run the process that initiated the event |
| **InitiatingProcessCreationTime** | Date and time when the process that initiated the event was started |
| **InitiatingProcessFileName** | Name of the process that initiated the event |
| **InitiatingProcessFileSize** | Size of the process (image file) that initiated the event |
| **InitiatingProcessFolderPath** | Folder containing the process (image file) that initiated the event |
| **InitiatingProcessId** | Process ID (PID) of the process that initiated the event |
| **InitiatingProcessIntegrityLevel** | Integrity level of the process that initiated the event. Windows assigns integrity levels to processes based on certain characteristics, such as if they were launched from an internet download. These integrity levels influence permissions to resources. |
| **InitiatingProcessMD5** | MD5 hash of the process (image file) that initiated the event |
| **InitiatingProcessParentCreationTime** | Date and time when the parent of the process responsible for the event was started |
| **InitiatingProcessParentFileName** | Name of the parent process that spawned the process responsible for the event |
| **InitiatingProcessParentId** | Process ID (PID) of the parent process that spawned the process responsible for the event |
| **InitiatingProcessSHA1** | SHA-1 hash of the process (image file) that initiated the event |
| **InitiatingProcessSHA256** | SHA-256 hash of the process (image file) that initiated the event. This field is usually not populated - use the SHA1 column when available. |
| **InitiatingProcessTokenElevation** | Token type indicating the presence or absence of User Access Control (UAC) privilege elevation applied to the process that initiated the event |
| **InitiatingProcessVersionInfoCompanyName** | Company name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoFileDescription** | Description from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoInternalFileName** | Internal file name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoOriginalFileName** | Original file name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoProductName** | Product name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoProductVersion** | Product version from the version information of the process (image file) responsible for the event |
| **IsLocalAdmin** | Boolean indicator of whether the user is a local administrator on the machine |
| **LogonId** | Identifier for a logon session. This identifier is unique on the same machine only between restarts |
| **LogonType** | Type of logon session, specifically interactive, remote interactive (RDP), network, batch, and service |
| **Protocol** | Protocol used during the communication |
| **RemoteDeviceName** | Name of the device that performed a remote operation on the affected machine. Depending on the event being reported, this name could be a fully-qualified domain name (FQDN), a NetBIOS name, or a host name without domain information. |
| **RemoteIP** | IP address that was being connected to |
| **RemoteIPType** | Type of IP address, for example Public, Private, Reserved, Loopback, Teredo, FourToSixMapping, and Broadcast |
| **RemotePort** | TCP port on the remote device that was being connected to |
| **ReportId** | Event identifier based on a repeating counter.To identify unique events, this column must be used in conjunction with the DeviceName and Timestamp columns. |
| **Timestamp** | Date and time when the record was generated |

### ActionTypes:
| ActionType | Description |
| --- | --- |
| **LogonAttempted** | A user attempted to log on to the device. |
| **LogonFailed** | A user attempted to logon to the device but failed. |
| **LogonSuccess** | A user successfully logged on to the device. |

### Examples:

### Get the 10 latest logons performed by accounts within 30 minutes of receiving a known malicious email. Use the logons to check whether the accounts have been compromised.
```
//Find logons that occurred right after malicious email was received
let MaliciousEmail=EmailEvents
| where ThreatTypes has "Malware" 
| project TimeEmail = Timestamp, Subject, SenderFromAddress, AccountName = tostring(split(RecipientEmailAddress, "@")[0]);
MaliciousEmail
| join (
DeviceLogonEvents
| project LogonTime = Timestamp, AccountName, DeviceName
) on AccountName 
| where (LogonTime - TimeEmail) between (0min.. 30min)
| take 10
```

### List authentication events by members of the local administrator group or the built-in administrator account
```
//List authentication events by members of the local administrator group or the built-in administrator account
let myDevice = "<insert your device ID>";
DeviceLogonEvents
| where  IsLocalAdmin == '1'  and Timestamp > ago(7d) and DeviceId == "00d20207bebd88fea19194bd775a372875c7ab1f"
| limit 500
```


## Table: DeviceNetworkEvents

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicenetworkevents-table?view=o365-worldwide)
**Description:** Network connection and related events

### Table Schema:
| Field | Description |
| --- | --- |
| **ActionType** | Type of activity that triggered the event |
| **AdditionalFields** | Additional information about the entity or event |
| **AppGuardContainerId** | Identifier for the virtualized container used by Application Guard to isolate browser activity |
| **DeviceId** | Unique identifier for the device in the service |
| **DeviceName** | Fully qualified domain name (FQDN) of the device |
| **InitiatingProcessAccountDomain** | Domain of the account that ran the process responsible for the event |
| **InitiatingProcessAccountName** | User name of the account that ran the process responsible for the event |
| **InitiatingProcessAccountObjectId** | Azure AD object ID of the user account that ran the process responsible for the event |
| **InitiatingProcessAccountSid** | Security Identifier (SID) of the account that ran the process responsible for the event |
| **InitiatingProcessAccountUpn** | User principal name (UPN) of the account that ran the process responsible for the event |
| **InitiatingProcessCommandLine** | Command line used to run the process that initiated the event |
| **InitiatingProcessCreationTime** | Date and time when the process that initiated the event was started |
| **InitiatingProcessFileName** | Name of the process that initiated the event |
| **InitiatingProcessFileSize** | Size of the process (image file) that initiated the event |
| **InitiatingProcessFolderPath** | Folder containing the process (image file) that initiated the event |
| **InitiatingProcessId** | Process ID (PID) of the process that initiated the event |
| **InitiatingProcessIntegrityLevel** | Integrity level of the process that initiated the event. Windows assigns integrity levels to processes based on certain characteristics, such as if they were launched from an internet download. These integrity levels influence permissions to resources. |
| **InitiatingProcessMD5** | MD5 hash of the process (image file) that initiated the event |
| **InitiatingProcessParentCreationTime** | Date and time when the parent of the process responsible for the event was started |
| **InitiatingProcessParentFileName** | Name of the parent process that spawned the process responsible for the event |
| **InitiatingProcessParentId** | Process ID (PID) of the parent process that spawned the process responsible for the event |
| **InitiatingProcessSHA1** | SHA-1 hash of the process (image file) that initiated the event |
| **InitiatingProcessSHA256** | SHA-256 hash of the process (image file) that initiated the event. This field is usually not populated - use the SHA1 column when available. |
| **InitiatingProcessTokenElevation** | Token type indicating the presence or absence of User Access Control (UAC) privilege elevation applied to the process that initiated the event |
| **InitiatingProcessVersionInfoCompanyName** | Company name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoFileDescription** | Description from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoInternalFileName** | Internal file name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoOriginalFileName** | Original file name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoProductName** | Product name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoProductVersion** | Product version from the version information of the process (image file) responsible for the event |
| **LocalIP** | IP address assigned to the local machine used during communication |
| **LocalIPType** | Type of IP address, for example Public, Private, Reserved, Loopback, Teredo, FourToSixMapping, and Broadcast |
| **LocalPort** | TCP port on the local machine used during communication |
| **Protocol** | Protocol used during the communication |
| **RemoteIP** | IP address that was being connected to |
| **RemoteIPType** | Type of IP address, for example Public, Private, Reserved, Loopback, Teredo, FourToSixMapping, and Broadcast |
| **RemotePort** | TCP port on the remote device that was being connected to |
| **RemoteUrl** | URL or fully qualified domain name (FQDN) that was being connected to |
| **ReportId** | Event identifier based on a repeating counter.To identify unique events, this column must be used in conjunction with the DeviceName and Timestamp columns. |
| **Timestamp** | Date and time when the record was generated |

### ActionTypes:
| ActionType | Description |
| --- | --- |
| **ConnectionFailed** | An attempt to establish a network connection from the device failed. |
| **ConnectionFound** | An active network connection was found on the device. |
| **ConnectionRequest** | The device initiated a network connection. |
| **ConnectionSuccess** | A network connection was successfully established from the device. |
| **FtpConnectionInspected** | The deep packet inspection engine in Microsoft Defender for Endpoint inspected an FTP connection. |
| **HttpConnectionInspected** | The deep packet inspection engine in Microsoft Defender for Endpoint inspected an HTTP connection. |
| **IcmpConnectionInspected** | The deep packet inspection engine in Microsoft Defender for Endpoint inspected an ICMP connection. |
| **InboundConnectionAccepted** | The device accepted a network connection initiated by another device. |
| **InboundInternetScanInspected** | An incoming packet from a Microsoft Defender External Attack Surface Management scan was inspected on the device. |
| **ListeningConnectionCreated** | A process has started listening for connections on a certain port. |
| **NetworkSignatureInspected** | A packet content was inspected. |
| **SmtpConnectionInspected** | The deep packet inspection engine in Microsoft Defender for Endpoint inspected an SMTP connection. |
| **SshConnectionInspected** | The deep packet inspection engine in Microsoft Defender for Endpoint inspected an SSH connection. |

### Examples:

### Check command lines used to launch PowerShell for strings that indicate download activity
```
// Finds PowerShell execution events that could involve a download
union DeviceProcessEvents, DeviceNetworkEvents
| where Timestamp > ago(7d)
// Pivoting on PowerShell processes
| where FileName in~ ("powershell.exe", "powershell_ise.exe")
// Suspicious commands
| where ProcessCommandLine has_any("WebClient",
 "DownloadFile",
 "DownloadData",
 "DownloadString",
"WebRequest",
"Shellcode",
"http",
"https")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, 
FileName, ProcessCommandLine, RemoteIP, RemoteUrl, RemotePort, RemoteIPType
| top 100 by Timestamp
```

### Find network connections by known Tor clients
```
//Find network connections by known Tor clients
DeviceNetworkEvents  
| where Timestamp > ago(7d) and InitiatingProcessFileName in~ ("tor.exe", "meek-client.exe")
// Returns MD5 hashes of files used by Tor, to enable you to block them.
// We count how prevalent each file is (by devices) and show examples for some of them (up to 5 device names per hash).
| summarize DeviceCount=dcount(DeviceId), DeviceNames=make_set(DeviceName, 5) by InitiatingProcessMD5
| order by DeviceCount desc
```


## Table: DeviceNetworkInfo

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicenetworkinfo-table?view=o365-worldwide)
**Description:** Network properties of machines, including adapters, IP and MAC addresses, as well as connected networks and domains

### Table Schema:
| Field | Description |
| --- | --- |
| **ConnectedNetworks** | Networks that the adapter is connected to. Each JSON element in the array contains the network name, category (public, private or domain), a description, and a flag indicating if itâ€™s connected publicly to the internet |
| **DefaultGateways** | Default gateway addresses in JSON array format |
| **DeviceId** | Unique identifier for the device in the service |
| **DeviceName** | Fully qualified domain name (FQDN) of the device |
| **DnsAddresses** | DNS server addresses in JSON array format |
| **IPAddresses** | JSON array containing all the IP addresses assigned to the adapter, along with their respective subnet prefix and the IP class (RFC 1918 & RFC 4291) |
| **IPv4Dhcp** | IPv4 address of DHCP server |
| **IPv6Dhcp** | IPv6 address of DHCP server |
| **MacAddress** | MAC address of the network adapter |
| **NetworkAdapterName** | Name of the network adapter |
| **NetworkAdapterStatus** | Operational status of the network adapter |
| **NetworkAdapterType** | Network adapter type |
| **NetworkAdapterVendor** | Name of the manufacturer or vendor of the network adapter |
| **ReportId** | Event identifier based on a repeating counter.To identify unique events, this column must be used in conjunction with the DeviceName and Timestamp columns. |
| **Timestamp** | Date and time when the record was generated |
| **TunnelType** | Tunneling protocol, if the interface is used for this purpose, for example 6to4, Teredo, ISATAP, PPTP, SSTP, and SSH |

### Examples:

### List all devices that have been assigned a specific IP address
```
let pivotTimeParam = datetime(2020-05-18 19:51:00);
let ipAddressParam = "192.168.1.5";
DeviceNetworkInfo
| where Timestamp between ((pivotTimeParam-15m) ..30m) 
    and IPAddresses contains strcat("\", ipAddressParam, \"") 
    and NetworkAdapterStatus == "Up"
//// Optional - add filters to make sure machine is part of the relevant network (and not using that IP address as part of another private network).
//// For example:
// and ConnectedNetworks contains "corp.contoso.com"
// and IPv4Dhcp == "10.164.3.12"
// and DefaultGateways contains "\"10.164.3.1\"
| project DeviceName, Timestamp, IPAddresses, TimeDifference=abs(Timestamp-pivotTimeParam)
// In case multiple machines have reported from that IP address arround that time, start with the ones reporting closest to pivotTimeParam
| sort by TimeDifference asc
```


## Table: DeviceProcessEvents

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-deviceprocessevents-table?view=o365-worldwide)
**Description:** Process creation and related events

### Table Schema:
| Field | Description |
| --- | --- |
| **AccountDomain** | Domain of the account |
| **AccountName** | User name of the account |
| **AccountObjectId** | Unique identifier for the account in Azure AD |
| **AccountSid** | Security Identifier (SID) of the account |
| **AccountUpn** | User principal name (UPN) of the account |
| **ActionType** | Type of activity that triggered the event |
| **AdditionalFields** | Additional information about the entity or event |
| **AppGuardContainerId** | Identifier for the virtualized container used by Application Guard to isolate browser activity |
| **DeviceId** | Unique identifier for the device in the service |
| **DeviceName** | Fully qualified domain name (FQDN) of the device |
| **FileName** | Name of the file that the recorded action was applied to |
| **FileSize** | Size of the file in bytes |
| **FolderPath** | Folder containing the file that the recorded action was applied to |
| **InitiatingProcessAccountDomain** | Domain of the account that ran the process responsible for the event |
| **InitiatingProcessAccountName** | User name of the account that ran the process responsible for the event |
| **InitiatingProcessAccountObjectId** | Azure AD object ID of the user account that ran the process responsible for the event |
| **InitiatingProcessAccountSid** | Security Identifier (SID) of the account that ran the process responsible for the event |
| **InitiatingProcessAccountUpn** | User principal name (UPN) of the account that ran the process responsible for the event |
| **InitiatingProcessCommandLine** | Command line used to run the process that initiated the event |
| **InitiatingProcessCreationTime** | Date and time when the process that initiated the event was started |
| **InitiatingProcessFileName** | Name of the process that initiated the event |
| **InitiatingProcessFileSize** | Size of the process (image file) that initiated the event |
| **InitiatingProcessFolderPath** | Folder containing the process (image file) that initiated the event |
| **InitiatingProcessId** | Process ID (PID) of the process that initiated the event |
| **InitiatingProcessIntegrityLevel** | Integrity level of the process that initiated the event. Windows assigns integrity levels to processes based on certain characteristics, such as if they were launched from an internet download. These integrity levels influence permissions to resources. |
| **InitiatingProcessLogonId** | Identifier for a logon session of the process that initiated the event. This identifier is unique on the same machine only between restarts. |
| **InitiatingProcessMD5** | MD5 hash of the process (image file) that initiated the event |
| **InitiatingProcessParentCreationTime** | Date and time when the parent of the process responsible for the event was started |
| **InitiatingProcessParentFileName** | Name of the parent process that spawned the process responsible for the event |
| **InitiatingProcessParentId** | Process ID (PID) of the parent process that spawned the process responsible for the event |
| **InitiatingProcessSHA1** | SHA-1 hash of the process (image file) that initiated the event |
| **InitiatingProcessSHA256** | SHA-256 hash of the process (image file) that initiated the event. This field is usually not populated - use the SHA1 column when available. |
| **InitiatingProcessSignatureStatus** | Information about the signature status of the process (image file) that initiated the event |
| **InitiatingProcessSignerType** | Type of file signer of the process (image file) that initiated the event |
| **InitiatingProcessTokenElevation** | Token type indicating the presence or absence of User Access Control (UAC) privilege elevation applied to the process that initiated the event |
| **InitiatingProcessVersionInfoCompanyName** | Company name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoFileDescription** | Description from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoInternalFileName** | Internal file name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoOriginalFileName** | Original file name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoProductName** | Product name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoProductVersion** | Product version from the version information of the process (image file) responsible for the event |
| **LogonId** | Identifier for a logon session. This identifier is unique on the same machine only between restarts |
| **MD5** | MD5 hash of the file that the recorded action was applied to |
| **ProcessCommandLine** | Command line used to create the new process |
| **ProcessCreationTime** | Date and time the process was created |
| **ProcessId** | Process ID (PID) of the newly created process |
| **ProcessIntegrityLevel** | Integrity level of the newly created process. Windows assigns integrity levels to processes based on certain characteristics, such as if they were launched from an internet downloaded. These integrity levels influence permissions to resources. |
| **ProcessTokenElevation** | Indicates the type of token elevation applied to the newly created process. Possible values: TokenElevationTypeLimited (restricted), TokenElevationTypeDefault (standard), and TokenElevationTypeFull (elevated) |
| **ProcessVersionInfoCompanyName** | Company name from the version information of the newly created process |
| **ProcessVersionInfoFileDescription** | Description from the version information of the newly created process |
| **ProcessVersionInfoInternalFileName** | Internal file name from the version information of the newly created process |
| **ProcessVersionInfoOriginalFileName** | Original file name from the version information of the newly created process |
| **ProcessVersionInfoProductName** | Product name from the version information of the newly created process |
| **ProcessVersionInfoProductVersion** | Product version from the version information of the newly created process |
| **ReportId** | Event identifier based on a repeating counter.To identify unique events, this column must be used in conjunction with the DeviceName and Timestamp columns. |
| **SHA1** | SHA-1 hash of the file that the recorded action was applied to |
| **SHA256** | SHA-256 of the file that the recorded action was applied to |
| **Timestamp** | Date and time when the record was generated |

### ActionTypes:
| ActionType | Description |
| --- | --- |
| **OpenProcess** | The OpenProcess function was called indicating an attempt to open a handle to a local process and potentially manipulate that process. |
| **ProcessCreated** | A process was launched on the device. |

### Examples:

### Check process command lines for attempts to clear event logs
```
//Check process command lines for attempts to clear event logs
let myDevice = "<insert your device ID>";
DeviceProcessEvents 
| where DeviceId == myDevice and Timestamp > ago(7d) and ((InitiatingProcessCommandLine contains "wevtutil" and (InitiatingProcessCommandLine contains ' cl ' or InitiatingProcessCommandLine contains ' clear ' or InitiatingProcessCommandLine contains ' clearev ' )) 
or (InitiatingProcessCommandLine contains ' wmic ' and InitiatingProcessCommandLine contains ' cleareventlog '))
```

### Find PowerShell activities that occur right after receiving an email from a malicious sender
```
// Finds PowerShell activities that occurred right after an email was received from a malicious sender
let MaliciousSender = "malicious.sender@domain.com";
EmailEvents
| where Timestamp > ago(7d)
| where SenderFromAddress =~ MaliciousSender
| project EmailRecievedTime = Timestamp, Subject, SenderFromAddress, AccountName = tostring(split(RecipientEmailAddress, "@")[0])
| join (
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "powershell.exe"
| where InitiatingProcessParentFileName =~ "outlook.exe"
| project ProcessCreateTime = Timestamp, AccountName, DeviceName, InitiatingProcessParentFileName, InitiatingProcessFileName, FileName, ProcessCommandLine
) on AccountName 
| where (ProcessCreateTime - EmailRecievedTime) between (0min .. 30min)
```


## Table: DeviceRegistryEvents

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-deviceregistryevents-table?view=o365-worldwide)
**Description:** Creation and modification of registry entries

### Table Schema:
| Field | Description |
| --- | --- |
| **ActionType** | Type of activity that triggered the event |
| **AppGuardContainerId** | Identifier for the virtualized container used by Application Guard to isolate browser activity |
| **DeviceId** | Unique identifier for the device in the service |
| **DeviceName** | Fully qualified domain name (FQDN) of the device |
| **InitiatingProcessAccountDomain** | Domain of the account that ran the process responsible for the event |
| **InitiatingProcessAccountName** | User name of the account that ran the process responsible for the event |
| **InitiatingProcessAccountObjectId** | Azure AD object ID of the user account that ran the process responsible for the event |
| **InitiatingProcessAccountSid** | Security Identifier (SID) of the account that ran the process responsible for the event |
| **InitiatingProcessAccountUpn** | User principal name (UPN) of the account that ran the process responsible for the event |
| **InitiatingProcessCommandLine** | Command line used to run the process that initiated the event |
| **InitiatingProcessCreationTime** | Date and time when the process that initiated the event was started |
| **InitiatingProcessFileName** | Name of the process that initiated the event |
| **InitiatingProcessFileSize** | Size of the process (image file) that initiated the event |
| **InitiatingProcessFolderPath** | Folder containing the process (image file) that initiated the event |
| **InitiatingProcessId** | Process ID (PID) of the process that initiated the event |
| **InitiatingProcessIntegrityLevel** | Integrity level of the process that initiated the event. Windows assigns integrity levels to processes based on certain characteristics, such as if they were launched from an internet download. These integrity levels influence permissions to resources. |
| **InitiatingProcessMD5** | MD5 hash of the process (image file) that initiated the event |
| **InitiatingProcessParentCreationTime** | Date and time when the parent of the process responsible for the event was started |
| **InitiatingProcessParentFileName** | Name of the parent process that spawned the process responsible for the event |
| **InitiatingProcessParentId** | Process ID (PID) of the parent process that spawned the process responsible for the event |
| **InitiatingProcessSHA1** | SHA-1 hash of the process (image file) that initiated the event |
| **InitiatingProcessSHA256** | SHA-256 hash of the process (image file) that initiated the event. This field is usually not populated - use the SHA1 column when available. |
| **InitiatingProcessTokenElevation** | Token type indicating the presence or absence of User Access Control (UAC) privilege elevation applied to the process that initiated the event |
| **InitiatingProcessVersionInfoCompanyName** | Company name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoFileDescription** | Description from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoInternalFileName** | Internal file name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoOriginalFileName** | Original file name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoProductName** | Product name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoProductVersion** | Product version from the version information of the process (image file) responsible for the event |
| **PreviousRegistryKey** | Original registry key before it was modified |
| **PreviousRegistryValueData** | Original data of the registry value before it was modified |
| **PreviousRegistryValueName** | Original name of the registry value before it was modified |
| **RegistryKey** | Registry key that the recorded action was applied to |
| **RegistryValueData** | Data of the registry value that the recorded action was applied to |
| **RegistryValueName** | Name of the registry value that the recorded action was applied to |
| **RegistryValueType** | Data type, such as binary or string, of the registry value that the recorded action was applied to |
| **ReportId** | Event identifier based on a repeating counter.To identify unique events, this column must be used in conjunction with the DeviceName and Timestamp columns. |
| **Timestamp** | Date and time when the record was generated |

### ActionTypes:
| ActionType | Description |
| --- | --- |
| **RegistryKeyCreated** | A registry key was created. |
| **RegistryKeyDeleted** | A registry key was deleted. |
| **RegistryKeyRenamed** | A registry key was renamed. |
| **RegistryValueDeleted** | A registry value was deleted. |
| **RegistryValueSet** | The data for a registry value was modified. |

### Examples:

### Check a specific device for the services set to automatically start with Windows
```
//Check a specific device for the services set to automatically start with Windows
let myDevice = "<insert your device ID>";
DeviceRegistryEvents
| where DeviceId == "35cc086a8bb43808f9586ee890b04a64726a60d6"//myDevice 
    and ActionType in ("RegistryValueSet") 
    and RegistryKey matches regex @"HKEY_LOCAL_MACHINE\\SYSTEM\\.*\\Services\\.*"  
    and RegistryValueName == "Start" and RegistryValueData == "2"
| limit 100
```

### Get the list of devices where certain Microsoft Defender ATP capabilities, such as real-time protection, have been turned off
```
//Detecting disabling of Defender:
DeviceRegistryEvents
| where RegistryKey has @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender" 
    and (RegistryValueName has "DisableRealtimeProtection" 
    or RegistryValueName has "DisableRealtimeMonitoring" 
    or RegistryValueName has "DisableBehaviorMonitoring" 
    or RegistryValueName has "DisableIOAVProtection" 
    or RegistryValueName has "DisableScriptScanning" 
    or RegistryValueName has "DisableBlockAtFirstSeen")
    // Where 1 means itâ€™s disabled.
and RegistryValueData has "1" and isnotempty(PreviousRegistryValueData) and Timestamp > ago(7d)
| project Timestamp, ActionType, DeviceId , DeviceName, RegistryKey, RegistryValueName , RegistryValueData,  PreviousRegistryValueData  
```


## Table: DeviceTvmBrowserExtensions

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicetvmbrowserextensions-table?view=o365-worldwide)
**Description:** Browser extension installations found on devices as shown in Threat & Vulnerability Management

### Table Schema:
| Field | Description |
| --- | --- |
| **BrowserName** | Name of the web browser with the extension |
| **DeviceId** | Unique identifier for the device in the service |
| **ExtensionDescription** | Description from the publisher about the extension |
| **ExtensionId** | Unique identifier for the browser extension |
| **ExtensionName** | Name of the extension |
| **ExtensionRisk** | Risk level for the extension based on the permissions it has requested |
| **ExtensionVendor** | Name of the vendor offering the extension |
| **ExtensionVersion** | Version number of the extension |
| **InstallationTime** | Date and time when the browser extension was first installed |
| **IsActivated** | Whether the extension is turned on or off on the devices |

## Table: DeviceTvmBrowserExtensionsKB

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicetvmbrowserextensionskb-table?view=o365-worldwide)
**Description:** Knowledge base of browser extension details and permission information used in the Threat & Vulnerability Management browser extensions page

### Table Schema:
| Field | Description |
| --- | --- |
| **BrowserName** | Name of the web browser with the extension |
| **ExtensionDescription** | Description from the publisher about the extension |
| **ExtensionId** | Unique identifier for the browser extension |
| **ExtensionName** | Name of the extension |
| **ExtensionRisk** | Risk level for the extension based on the permissions it has requested |
| **ExtensionVersion** | Version number of the extension |
| **IsPermissionRequired** | Whether the permission is required for the extension to run, or optional |
| **PermissionDescription** | Explanation of what the permission is supposed to do |
| **PermissionId** | Unique identifier for the permission |
| **PermissionName** | Name given to each permission based on what the extension is asking for |
| **PermissionRisk** | Risk level for the permission based on the type of access it would allow |

## Table: DeviceTvmCertificateInfo

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicetvmcertificateinfo-table?view=o365-worldwide)
**Description:** Certificate information for devices in the organization

### Table Schema:
| Field | Description |
| --- | --- |
| **DeviceId** | Unique identifier for the device in the service |
| **ExpirationDate** | The date and time beyond which the certificate is no longer valid |
| **ExtendedKeyUsage** | Other valid uses for the certificate |
| **FriendlyName** | Easy-to-understand version of a certificate's title |
| **IssueDate** | The earliest date and time when the certificate became valid |
| **IssuedBy** | Entity that verified the information and signed the certificate |
| **IssuedTo** | Entity that a certificate belongs to; can be a device, an individual, or an organization |
| **KeySize** | Size of the key used in the signature algorithm |
| **KeyUsage** | The valid cryptographic uses of the certificate's public key |
| **Path** | The location of the certificate |
| **SerialNumber** | Unique identifier for the certificate within a certificate authority's systems |
| **SignatureAlgorithm** | Hashing algorithm and encryption algorithm used |
| **SubjectType** | Indicates if the holder of the certificate is a CA or end entity |
| **Thumbprint** | Unique identifier for the certificate |

## Table: DeviceTvmHardwareFirmware

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicetvmhardwarefirmware-table?view=o365-worldwide)
**Description:** The DeviceTvmHardwareFirmware table will hold information about device hardware and firmware, e.g. system model, processor, BIOS, chipset, TPM, Intel ME, etc.

### Table Schema:
| Field | Description |
| --- | --- |
| **AdditionalFields** | Additional information about the entity or event |
| **ComponentFamily** | Component family or class, a grouping of components that have similar features or characteristics as determined by the manufacturer |
| **ComponentName** | Name of hardware or firmware component |
| **ComponentType** | Type of hardware or firmware component |
| **ComponentVersion** | Component version (e.g., BIOS version) |
| **DeviceId** | Unique identifier for the device in the service |
| **DeviceName** | Fully qualified domain name (FQDN) of the device |
| **Manufacturer** | Manufacturer of hardware or firmware component |

### Examples:

### Count the number of Lenovo devices
```
DeviceTvmHardwareFirmware
| where ComponentType == 'Hardware' and Manufacturer == 'lenovo'
| summarize count()
```

### Find all devices with specific BIOS version
```
DeviceTvmHardwareFirmware
| where ComponentType == 'Bios' and ComponentVersion contains '<insert a BIOS version>'
|project DeviceId, DeviceName
```


## Table: DeviceTvmInfoGathering

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicetvminfogathering-table?view=o365-worldwide)
**Description:** The DeviceTvmInfoGathering table contains Threat & Vulnerability Management assessment events including the status of various configurations and attack surface area states of devices.

### Table Schema:
| Field | Description |
| --- | --- |
| **AdditionalFields** | Additional information about the entity or event |
| **DeviceId** | Unique identifier for the device in the service |
| **DeviceName** | Fully qualified domain name (FQDN) of the device |
| **LastSeenTime** | Date and time when the service last saw the device |
| **OSPlatform** | Platform of the operating system running on the device. This indicates specific operating systems, including variations within the same family, such as Windows 10 and Windows 7 |
| **Timestamp** | Date and time when the record was generated |

## Table: DeviceTvmInfoGatheringKB

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicetvminfogatheringkb-table?view=o365-worldwide)
**Description:** The DeviceTvmInfoGatheringKB table contains the list of various configuration and attack surface area assessments used by Threat & Vulnerability Management information gathering to assess devices

### Table Schema:
| Field | Description |
| --- | --- |
| **Categories** | List of categories that the information belongs to, in JSON array format |
| **DataStructure** | The data structure of the information gathered |
| **Description** | Description of the information gathered |
| **FieldName** | Name of the field where this information appears in the AdditionalFields column of the DeviceTvmInfoGathering table |
| **IgId** | Unique identifier for the piece of information gathered |

## Table: DeviceTvmSecureConfigurationAssessment

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicetvmsecureconfigurationassessment-table?view=o365-worldwide)
**Description:** Threat & Vulnerability Management assessment events, indicating the status of various security configurations on devices

### Table Schema:
| Field | Description |
| --- | --- |
| **ConfigurationCategory** | Category or grouping to which the configuration belongs |
| **ConfigurationId** | Unique identifier for a specific configuration |
| **ConfigurationImpact** | Rated impact of the configuration to the overall configuration score (1-10) |
| **ConfigurationSubcategory** | Subcategory or subgrouping to which the configuration belongs. In many cases, this describes specific capabilities or features. |
| **Context** | Configuration context data of the machine |
| **DeviceId** | Unique identifier for the device in the service |
| **DeviceName** | Fully qualified domain name (FQDN) of the device |
| **IsApplicable** | Indicates whether the configuration or policy is applicable |
| **IsCompliant** | Indicates whether the configuration or policy is properly configured |
| **IsExpectedUserImpact** | Indicates whether there will be user impact if the configuration will be applied |
| **OSPlatform** | Platform of the operating system running on the device. This indicates specific operating systems, including variations within the same family, such as Windows 10 and Windows 7 |
| **Timestamp** | Date and time when the record was generated |

## Table: DeviceTvmSecureConfigurationAssessmentKB

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicetvmsecureconfigurationassessmentkb-table?view=o365-worldwide)
**Description:** Knowledge base of various security configurations used by Threat & Vulnerability Management to assess devices; includes mappings to various standards and benchmarks

### Table Schema:
| Field | Description |
| --- | --- |
| **ConfigurationBenchmarks** | List of industry benchmarks recommending the same or similar configuration |
| **ConfigurationCategory** | Category or grouping to which the configuration belongs |
| **ConfigurationDescription** | Description of the configuration |
| **ConfigurationId** | Unique identifier for a specific configuration |
| **ConfigurationImpact** | Rated impact of the configuration to the overall configuration score (1-10) |
| **ConfigurationName** | Display name of the configuration |
| **ConfigurationSubcategory** | Subcategory or subgrouping to which the configuration belongs. In many cases, this describes specific capabilities or features. |
| **RemediationOptions** | Recommended actions to reduce or address any associated risks |
| **RiskDescription** | Description of any associated risks |
| **Tags** | Labels representing various attributes used to identify or categorize a security configuration |

## Table: DeviceTvmSoftwareEvidenceBeta

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicetvmsoftwareevidencebeta-table?view=o365-worldwide)
**Description:** Evidence indicating the existence of a software on a device based on registry paths, disk paths, or both.

### Table Schema:
| Field | Description |
| --- | --- |
| **DeviceId** | Unique identifier for the device in the service |
| **DiskPaths** | Disk paths on which file level evidence indicating the existence of a software on a device was detected |
| **LastSeenTime** | Date and time when the service last saw the device |
| **RegistryPaths** | Registry paths on which evidence indicating the existence of a software on a device was detected |
| **SoftwareName** | Name of the software product |
| **SoftwareVendor** | Name of the software vendor |
| **SoftwareVersion** | Version number of the software product |

## Table: DeviceTvmSoftwareInventory

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicetvmsoftwareinventory-table?view=o365-worldwide)
**Description:** Inventory of software installed on devices, including their version information and end-of-support status

### Table Schema:
| Field | Description |
| --- | --- |
| **DeviceId** | Unique identifier for the device in the service |
| **DeviceName** | Fully qualified domain name (FQDN) of the device |
| **EndOfSupportDate** | End-of-support (EOS) or end-of-life (EOL) date of the software product |
| **EndOfSupportStatus** | Indicates the lifecycle stage of the software product relative to its specified end-of-support (EOS) or end-of-life (EOL) date |
| **OSArchitecture** | Architecture of the operating system running on the machine |
| **OSPlatform** | Platform of the operating system running on the device. This indicates specific operating systems, including variations within the same family, such as Windows 10 and Windows 7 |
| **OSVersion** | Version of the operating system running on the machine |
| **ProductCodeCpe** | The standard Common Platform Enumeration (CPE) name of the software product version |
| **SoftwareName** | Name of the software product |
| **SoftwareVendor** | Name of the software vendor |
| **SoftwareVersion** | Version number of the software product |

### Examples:

### List software titles which are not supported anymore and the number of devices with these titles
```
//List software titles which are not supported anymore
DeviceTvmSoftwareInventory
| where EndOfSupportStatus == 'EOS Software'
| summarize dcount(DeviceId ) by SoftwareName
```


## Table: DeviceTvmSoftwareVulnerabilities

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicetvmsoftwarevulnerabilities-table?view=o365-worldwide)
**Description:** Software vulnerabilities found on devices and the list of available security updates that address each vulnerability

### Table Schema:
| Field | Description |
| --- | --- |
| **CveId** | Unique identifier assigned to the security vulnerability under the Common Vulnerabilities and Exposures (CVE) system |
| **CveMitigationStatus** | Indicates the status of the workaround mitigation for the CVE on this device (possible values: applied, not applied, partially applied, pending reboot) |
| **CveTags** | Array of tags relevant to the CVE; example: ZeroDay, NoSecurityUpdate |
| **DeviceId** | Unique identifier for the device in the service |
| **DeviceName** | Fully qualified domain name (FQDN) of the device |
| **OSArchitecture** | Architecture of the operating system running on the machine |
| **OSPlatform** | Platform of the operating system running on the device. This indicates specific operating systems, including variations within the same family, such as Windows 10 and Windows 7 |
| **OSVersion** | Version of the operating system running on the machine |
| **RecommendedSecurityUpdate** | Name or description of the security update provided by the software vendor to address the vulnerability |
| **RecommendedSecurityUpdateId** | Identifier of the applicable security updates or identifier for the corresponding guidance or knowledge base (KB) articles |
| **SoftwareName** | Name of the software product |
| **SoftwareVendor** | Name of the software vendor |
| **SoftwareVersion** | Version number of the software product |
| **VulnerabilitySeverityLevel** | Severity level assigned to the security vulnerability based on the CVSS score and dynamic factors influenced by the threat landscape |

### Examples:

### List devices affected by a specific vulnerability
```
DeviceTvmSoftwareVulnerabilities
| where CveId == 'CVE-2020-0791'
| limit 100
```


## Table: DeviceTvmSoftwareVulnerabilitiesKB

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicetvmsoftwarevulnerabilitieskb-table?view=o365-worldwide)
**Description:** Knowledge base of publicly disclosed vulnerabilities, including whether exploit code is publicly available

### Table Schema:
| Field | Description |
| --- | --- |
| **AffectedSoftware** | List of all software products affected by the vulnerability |
| **CveId** | Unique identifier assigned to the security vulnerability under the Common Vulnerabilities and Exposures (CVE) system |
| **CvssScore** | Severity score assigned to the security vulnerability under the Common Vulnerability Scoring System (CVSS) |
| **IsExploitAvailable** | Indicates whether exploit code for the vulnerability is publicly available |
| **LastModifiedTime** | Date and time the item or related metadata was last modified |
| **PublishedDate** | Date vulnerability was disclosed to the public |
| **VulnerabilityDescription** | Description of the vulnerability and associated risks |
| **VulnerabilitySeverityLevel** | Severity level assigned to the security vulnerability based on the CVSS score and dynamic factors influenced by the threat landscape |

### Examples:

### Get all information on a specific vulnerability
```
DeviceTvmSoftwareVulnerabilitiesKB
| where CveId == 'CVE-2020-0791'
```

### List vulnerabilities that have an available exploit and were publishde in the last week.
```
//List vulnerabilities that have an available exploit and were published in the last week.
DeviceTvmSoftwareVulnerabilitiesKB
| where IsExploitAvailable == True and PublishedDate > ago(7d)
| limit 100
```


## Table: EmailAttachmentInfo

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-emailattachmentinfo-table?view=o365-worldwide)
**Description:** Information about files attached to Office 365 emails

### Table Schema:
| Field | Description |
| --- | --- |
| **DetectionMethods** | Methods used to detect malware, phishing, or other threats found in the email |
| **FileName** | Name of the file that the recorded action was applied to |
| **FileSize** | Size of the file in bytes |
| **FileType** | File extension type |
| **NetworkMessageId** | Unique identifier for the email, generated by Office 365 |
| **RecipientEmailAddress** | Email address of the recipient, or email address of the recipient after distribution list expansion |
| **RecipientObjectId** | Unique identifier for the email recipient in Azure AD |
| **ReportId** | Unique identifier for the event |
| **SenderDisplayName** | Name of the sender displayed in the address book, typically a combination of a given or first name, a middle initial, and a last name or surname |
| **SenderFromAddress** | Sender email address in the FROM header, which is visible to email recipients on their email clients |
| **SenderObjectId** | Unique identifier for the senderâ€™s account in Azure AD |
| **SHA256** | SHA-256 of the file that the recorded action was applied to |
| **ThreatNames** | Detection name for malware or other threats found |
| **ThreatTypes** | Verdict from the email filtering stack on whether the email contains malware, phishing, or other threats |
| **Timestamp** | Date and time when the record was generated |

### Examples:

### Find the appearance of files sent by a specific malicious sender on devices on the network
```
// Finds the first appearance of files sent by a malicious sender in your organization
let MaliciousSender = "<insert the sender email address>";
EmailAttachmentInfo
| where Timestamp > ago(7d)
| where SenderFromAddress =~ MaliciousSender
| project SHA256 = tolower(SHA256)
| join (
DeviceFileEvents
| where Timestamp > ago(7d)
) on SHA256
| summarize FirstAppearance = min(Timestamp) by DeviceName, SHA256, FileName
```

### List all email messages with attachments that were sent to external domains
```
EmailEvents
| where EmailDirection == "Outbound" and AttachmentCount > 0
| join EmailAttachmentInfo on NetworkMessageId 
| project Timestamp, Subject, SenderFromAddress, RecipientEmailAddress, NetworkMessageId, FileName, AttachmentCount 
| take 100
```


## Table: EmailEvents

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-emailevents-table?view=o365-worldwide)
**Description:** Office 365 email events, including email delivery and blocking events

### Table Schema:
| Field | Description |
| --- | --- |
| **AdditionalFields** | Additional information about the entity or event |
| **AttachmentCount** | Number of attachments in the email |
| **AuthenticationDetails** | List of pass or fail verdicts by email authentication protocols like DMARC, DKIM, SPF or a combination of multiple authentication types (CompAuth) |
| **BulkComplaintLevel** | Threshold assigned to email from bulk mailers, a high bulk complain level (BCL) means the email is more likely to generate complaints, and thus more likely to be spam |
| **ConfidenceLevel** | List of confidence levels of any spam or phishing verdicts. For spam, this column shows the spam confidence level (SCL), indicating if the email was skipped (-1), found to be not spam (0,1), found to be spam with moderate confidence (5,6), or found to be spam with high confidence (9). For phishing, this column displays whether the confidence level is "High" or "Low". |
| **Connectors** | Custom instructions that define organizational mail flow and how the email was routed |
| **DeliveryAction** | Delivery action of the email: Delivered, Junked, Blocked, or Replaced |
| **DeliveryLocation** | Location where the email was delivered: Inbox/Folder, On-premises/External, Junk, Quarantine, Failed, Dropped, Deleted items |
| **DetectionMethods** | Methods used to detect malware, phishing, or other threats found in the email |
| **EmailAction** | Final action taken on the email based on filter verdict, policies, and user actions:  Move message to junk mail folder, Add X-header, Modify subject, Redirect message, Delete message, send to quarantine, No action taken, Bcc message |
| **EmailActionPolicy** | Action policy that took effect: Antispam high-confidence, Antispam, Antispam bulk mail, Antispam phishing, Anti-phishing domain impersonation, Anti-phishing user impersonation, Anti-phishing spoof, Anti-phishing graph impersonation, Antimalware Safe Attachments, Enterprise Transport Rules (ETR) |
| **EmailActionPolicyGuid** | Unique identifier for the policy that determined the final mail action |
| **EmailClusterId** | Identifier for the group of similar emails clustered based on heuristic analysis of their contents |
| **EmailDirection** | Direction of the email relative to your network:  Inbound, Outbound, Intra-org |
| **EmailLanguage** | Detected language of the email content |
| **InternetMessageId** | Public-facing identifier for the email that is set by the sending email system |
| **NetworkMessageId** | Unique identifier for the email, generated by Office 365 |
| **OrgLevelAction** | Action taken on the email in response to matches to a policy defined at the organizational level |
| **OrgLevelPolicy** | Organizational policy that triggered the action taken on the email |
| **RecipientEmailAddress** | Email address of the recipient, or email address of the recipient after distribution list expansion |
| **RecipientObjectId** | Unique identifier for the email recipient in Azure AD |
| **ReportId** | Unique identifier for the event |
| **SenderDisplayName** | Name of the sender displayed in the address book, typically a combination of a given or first name, a middle initial, and a last name or surname |
| **SenderFromAddress** | Sender email address in the FROM header, which is visible to email recipients on their email clients |
| **SenderFromDomain** | Sender domain in the FROM header, which is visible to email recipients on their email clients |
| **SenderIPv4** | IPv4 address of the last detected mail server that relayed the message |
| **SenderIPv6** | IPv6 address of the last detected mail server that relayed the message |
| **SenderMailFromAddress** | Sender email address in the MAIL FROM header, also known as the envelope sender or the Return-Path address |
| **SenderMailFromDomain** | Sender domain in the MAIL FROM header, also known as the envelope sender or the Return-Path address |
| **SenderObjectId** | Unique identifier for the senderâ€™s account in Azure AD |
| **Subject** | Subject of the email |
| **ThreatNames** | Detection name for malware or other threats found |
| **ThreatTypes** | Verdict from the email filtering stack on whether the email contains malware, phishing, or other threats |
| **Timestamp** | Date and time when the record was generated |
| **UrlCount** | Number of embedded URLs in the email |
| **UserLevelAction** | Action taken on the email in response to matches to a mailbox policy defined by the recipient |
| **UserLevelPolicy** | End user mailbox policy that triggered the action taken on the email |

### Examples:

### Get the number of phishing emails from the top ten sender domains
```
//Get the number of phishing emails from the top ten sender domains
EmailEvents
| where ThreatTypes has "Phish"
| summarize Count = count() by SenderFromDomain
| top 10 by Count
```

### List all email messages found containing malware
```
EmailEvents
| where ThreatTypes has "Malware"
| limit 500
```


## Table: EmailPostDeliveryEvents

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-emailpostdeliveryevents-table?view=o365-worldwide)
**Description:** Security events that occur post-delivery, after Office 365 has delivered an email message to the recipient mailbox

### Table Schema:
| Field | Description |
| --- | --- |
| **Action** | Action taken on the entity |
| **ActionResult** | Result of the action |
| **ActionTrigger** | Indicates whether an action was triggered by an administrator (manually or through approval of a pending automated action), or by some special mechanism, such as a ZAP or Dynamic Delivery |
| **ActionType** | Type of activity that triggered the event |
| **DeliveryLocation** | Location where the email was delivered: Inbox/Folder, On-premises/External, Junk, Quarantine, Failed, Dropped, Deleted items |
| **DetectionMethods** | Methods used to detect malware, phishing, or other threats found in the email |
| **InternetMessageId** | Public-facing identifier for the email that is set by the sending email system |
| **NetworkMessageId** | Unique identifier for the email, generated by Office 365 |
| **RecipientEmailAddress** | Email address of the recipient, or email address of the recipient after distribution list expansion |
| **ReportId** | Unique identifier for the event |
| **ThreatTypes** | Verdict from the email filtering stack on whether the email contains malware, phishing, or other threats |
| **Timestamp** | Date and time when the record was generated |

### ActionTypes:
| ActionType | Description |
| --- | --- |
| **Malware ZAP** | Zero-hour auto purge (ZAP) took action on an email message found containing malware after delivery. |
| **Manual Remediation** | An administrator manually took action on an email message after it was delivered to the user mailbox. This includes actions taken manually through Threat Explorer or approvals of automated investigation and response (AIR) actions. |
| **Phish ZAP** | Zero-hour auto purge (ZAP) took action on a phishing email after delivery. |
| **Spam ZAP** | Zero-hour auto purge (ZAP) took action on spam email after delivery. |

### Examples:

### Find unremediated emails that were identified as phishing after delivery
```
EmailPostDeliveryEvents
| where ActionType == 'Phish ZAP' and ActionResult == 'Error'
| join EmailEvents on NetworkMessageId, RecipientEmailAddress 
```

### Get detailed processing information up until post-delivery of an email with a specific subject from a particular sender
```
let mySender = "<insert sender email address>";
let subject = "<insert email subject>";
EmailEvents
| where SenderFromAddress == mySender and Subject == subject
| join EmailPostDeliveryEvents on NetworkMessageId, RecipientEmailAddress
```

### List all actions taken or approved by administrators manually on emails after delivery
```
EmailPostDeliveryEvents
| where ActionTrigger == 'AdminAction'
| limit 100
```


## Table: EmailUrlInfo

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-emailurlinfo-table?view=o365-worldwide)
**Description:** Information about URLs on Office 365 emails

### Table Schema:
| Field | Description |
| --- | --- |
| **NetworkMessageId** | Unique identifier for the email, generated by Office 365 |
| **ReportId** | Unique identifier for the event |
| **Timestamp** | Date and time when the record was generated |
| **Url** | Full Url from email |
| **UrlDomain** | Domain name or host name of the URL |
| **UrlLocation** | Indicates which part of the email the URL is located |

### Examples:

### List all URLs in the body of a specific email
```
let myEmailId = "<insert your email NetworkMessageId>";
EmailEvents
| where NetworkMessageId == myEmailId
| join EmailUrlInfo on NetworkMessageId
| project Timestamp, Subject, SenderFromAddress, RecipientEmailAddress, NetworkMessageId, Url, UrlCount
```


## Table: IdentityDirectoryEvents

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-identitydirectoryevents-table?view=o365-worldwide)
**Description:** Events involving a domain controller or a directory service, such as Active Directory (AD ) or Azure AD

### Table Schema:
| Field | Description |
| --- | --- |
| **AccountDisplayName** | Name displayed in the address book entry for the account user. This is usually a combination of the given name, middle initial, and surname of the user. |
| **AccountDomain** | Domain of the account |
| **AccountName** | User name of the account |
| **AccountObjectId** | Unique identifier for the account in Azure AD |
| **AccountSid** | Security Identifier (SID) of the account |
| **AccountUpn** | User principal name (UPN) of the account |
| **ActionType** | Type of activity that triggered the event |
| **AdditionalFields** | Additional information about the entity or event |
| **Application** | Application that performed the recorded action |
| **DestinationDeviceName** | Name of the device running the server application that processed the recorded action |
| **DestinationIPAddress** | IP address of the device running the server application that processed the recorded action |
| **DestinationPort** | Destination port of the activity |
| **DeviceName** | Fully qualified domain name (FQDN) of the device |
| **IPAddress** | IP address assigned to the device during communication |
| **ISP** | Internet service provider associated with  the IP address |
| **Location** | City, country, or other geographic location associated with the event |
| **Port** | TCP port used during communication |
| **Protocol** | Protocol used during the communication |
| **ReportId** | Unique identifier for the event |
| **TargetAccountDisplayName** | Display name of the account that the recorded action was applied to |
| **TargetAccountUpn** | User principal name (UPN) of the account that the recorded action was applied to |
| **TargetDeviceName** | Fully qualified domain name (FQDN) of the device that the recorded action was applied to |
| **Timestamp** | Date and time when the record was generated |

### ActionTypes:
| ActionType | Description |
| --- | --- |
| **Account Constrained Delegation SPNs changed** | Constrained delegation restricts the services to which the specified server can act on behalf of the user. |
| **Account Constrained Delegation State changed** | The account state is now enabled or disabled for delegation. |
| **Account Delegation changed** | The account state is now enabled or disabled for delegation. |
| **Account Deleted changed** | User account was deleted. |
| **Account Disabled changed** | Indicates whether an account is disabled or enabled. |
| **Account Display Name changed** | User's display name was changed. |
| **Account expired** | Date when the account expires. |
| **Account Expiry Time changed** | Change to the date when the account expires. |
| **Account Locked changed** | Change to the date when the account expires. |
| **Account Name changed** | User's name was changed. |
| **Account Password changed** | User changed their password. |
| **Account Password expired** | User's password expired. |
| **Account Password Never Expires changed** | User's password changed to never expire. |
| **Account Password Not Required changed** | User account was changed allow logging in with a blank password. |
| **Account Path changed** | User Distinguished name was changed from X to Y. |
| **Account Smart Card Required changed** | Account changes to require users to log on to a device using a smart card. |
| **Account Supported Encryption Types changed** | Kerberos supported encryption types were changed(types: Des, AES 129, AES 256). |
| **Account Upn Name changed** | User's principle name was changed. |
| **Device Account Created** | A new device account was created. |
| **Device Operating System changed** | An operating system attribute was changed. |
| **Directory Service replication** | User tried to replicate the directory service. |
| **Group Membership changed** | User was added/removed, to/from a group, by another user or by themselves. |
| **Potential lateral movement path identified** | Identified potential lateral movement path to a sensitive user. |
| **PowerShell execution** | User attempted to remotely execute a PowerShell command. |
| **Private Data Retrieval** | User attempted/succeeded to query private data using LSARPC protocol. |
| **Security Principal created** | Account was created (both user and computer). |
| **Security Principal deleted changed** | Account was deleted/restored (both user and computer). |
| **Security Principal Display Name changed** | Account display name was changed from X to Y. |
| **Security Principal Name changed** | Account name attribute was changed. |
| **Security Principal Path changed** | Account Distinguished name was changed from X to Y. |
| **Security Principal Sam Name changed** | SAM name changed (SAM is the logon name used to support clients and servers running earlier versions of the operating system). |
| **Service creation** | User attempted to remotely create a specific service to a remote machine. |
| **SMB session** | User attempted to enumerate all users with open SMB sessions on the domain controllers. |
| **SmbFileCopy** | User copied files using SMB. |
| **Task scheduling** | User tried to remotely schedule X task to a remote machine. |
| **User Mail changed** | Users email attribute was changed. |
| **User Manager changed** | User's manager attribute was changed. |
| **User Phone Number changed** | User's phone number attribute was changed. |
| **User Title changed** | User's title attribute was changed. |
| **Wmi execution** | User attempted to remotely execute a WMI method. |

### Examples:

### Find the latest password change event for a specific account
```
//Find the latest password change event for a specific account
let userAccount = '<insert your user account>';
let deviceAccount = 'insert your device account';
IdentityDirectoryEvents
| where ActionType == 'Account Password changed'
| where TargetAccountDisplayName == userAccount
//If you are looking for last password change of a device account comment the above row and remove comment from the below row
//| where TargetDeviceName == deviceAccount
| summarize LastPasswordChangeTime = max(Timestamp) by TargetAccountDisplayName // or change to TargetDeviceName for devcie account
```

### List changes made to a specific group
```
let group = '<insert your group>';
IdentityDirectoryEvents
| where ActionType == 'Group Membership changed'
| extend AddedToGroup = AdditionalFields['TO.GROUP']
| extend RemovedFromGroup = AdditionalFields['FROM.GROUP']
| extend TargetAccount = AdditionalFields['TARGET_OBJECT.USER']
| where AddedToGroup == group or RemovedFromGroup == group
| project-reorder Timestamp, ActionType, AddedToGroup, RemovedFromGroup, TargetAccount
| limit 100
```


## Table: IdentityInfo

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-identityinfo-table?view=o365-worldwide)
**Description:** Account information from various sources, including Azure Active Directory

### Table Schema:
| Field | Description |
| --- | --- |
| **AccountDisplayName** | Name displayed in the address book entry for the account user. This is usually a combination of the given name, middle initial, and surname of the user. |
| **AccountDomain** | Domain of the account |
| **AccountName** | User name of the account |
| **AccountObjectId** | Unique identifier for the account in Azure AD |
| **AccountUpn** | User principal name (UPN) of the account |
| **City** | City where the client IP address is geolocated |
| **CloudSid** | Cloud security identifier of the account |
| **Country** | Country/Region where the account user is located |
| **Department** | Name of the department that the account user belongs to |
| **EmailAddress** | SMTP address of the account |
| **GivenName** | Given name or first name of the account user |
| **IsAccountEnabled** | Indicates whether the account is enabled or not |
| **JobTitle** | Job title of the account user |
| **OnPremSid** | On-premises security identifier (SID) of the account |
| **SipProxyAddress** | Voice of over IP (VOIP) session initiation protocol (SIP) address of the account |
| **Surname** | Surname, family name, or last name of the account user |

### Examples:

### List all users in a specific department
```
let MyDepartment= "<insert your department>";
IdentityInfo 
| where Department == MyDepartment
| summarize by AccountObjectId, AccountUpn 
```

### List all users located in a particular country
```
let MyCountry= "<insert your contry>";
IdentityInfo 
| where Country  == MyCountry
| summarize by AccountObjectId, AccountUpn 
```


## Table: IdentityLogonEvents

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-identitylogonevents-table?view=o365-worldwide)
**Description:** Authentication events recorded by Active Directory and other Microsoft online services

### Table Schema:
| Field | Description |
| --- | --- |
| **AccountDisplayName** | Name displayed in the address book entry for the account user. This is usually a combination of the given name, middle initial, and surname of the user. |
| **AccountDomain** | Domain of the account |
| **AccountName** | User name of the account |
| **AccountObjectId** | Unique identifier for the account in Azure AD |
| **AccountSid** | Security Identifier (SID) of the account |
| **AccountUpn** | User principal name (UPN) of the account |
| **ActionType** | Type of activity that triggered the event |
| **AdditionalFields** | Additional information about the entity or event |
| **Application** | Application that performed the recorded action |
| **DestinationDeviceName** | Name of the device running the server application that processed the recorded action |
| **DestinationIPAddress** | IP address of the device running the server application that processed the recorded action |
| **DestinationPort** | Destination port of the activity |
| **DeviceName** | Fully qualified domain name (FQDN) of the device |
| **DeviceType** | Type of device based on purpose and functionality, such as network device, workstation, server, mobile, gaming console, or printer |
| **FailureReason** | Information explaining why the recorded action failed |
| **IPAddress** | IP address assigned to the device during communication |
| **ISP** | Internet service provider associated with  the IP address |
| **Location** | City, country, or other geographic location associated with the event |
| **LogonType** | Type of logon session, specifically interactive, remote interactive (RDP), network, batch, and service |
| **OSPlatform** | Platform of the operating system running on the device. This indicates specific operating systems, including variations within the same family, such as Windows 10 and Windows 7 |
| **Port** | TCP port used during communication |
| **Protocol** | Protocol used during the communication |
| **ReportId** | Unique identifier for the event |
| **TargetAccountDisplayName** | Display name of the account that the recorded action was applied to |
| **TargetDeviceName** | Fully qualified domain name (FQDN) of the device that the recorded action was applied to |
| **Timestamp** | Date and time when the record was generated |

### ActionTypes:
| ActionType | Description |
| --- | --- |
| **LogonFailed** | A user attempted to logon to the device but failed. |
| **LogonSuccess** | A user successfully logged on to the device. |

### Examples:

### Find LDAP authentication attempts using cleartext passwords
```
// Find processes that performed LDAP authentication with cleartext passwords
IdentityLogonEvents
| where Timestamp > ago(7d)
| where Protocol == "LDAP" //and isnotempty(AccountName)
| project LogonTime = Timestamp, DeviceName, Application, ActionType, LogonType //,AccountName
| join kind=inner (
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "ConnectionSuccess"
| extend DeviceName = toupper(trim(@"\..*$",DeviceName))
| where RemotePort == "389"
| project NetworkConnectionTime = Timestamp, DeviceName, AccountName = InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine  
) on DeviceName
| where LogonTime - NetworkConnectionTime between (-2m .. 2m)
| project Application, LogonType, ActionType, LogonTime, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine //, AccountName
```


## Table: IdentityQueryEvents

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-identityqueryevents-table?view=o365-worldwide)
**Description:** Query activities performed against Active Directory objects, such as users, groups, devices, and domains

### Table Schema:
| Field | Description |
| --- | --- |
| **AccountDisplayName** | Name displayed in the address book entry for the account user. This is usually a combination of the given name, middle initial, and surname of the user. |
| **AccountDomain** | Domain of the account |
| **AccountName** | User name of the account |
| **AccountObjectId** | Unique identifier for the account in Azure AD |
| **AccountSid** | Security Identifier (SID) of the account |
| **AccountUpn** | User principal name (UPN) of the account |
| **ActionType** | Type of activity that triggered the event |
| **AdditionalFields** | Additional information about the entity or event |
| **Application** | Application that performed the recorded action |
| **DestinationDeviceName** | Name of the device running the server application that processed the recorded action |
| **DestinationIPAddress** | IP address of the device running the server application that processed the recorded action |
| **DestinationPort** | Destination port of the activity |
| **DeviceName** | Fully qualified domain name (FQDN) of the device |
| **IPAddress** | IP address assigned to the device during communication |
| **Location** | City, country, or other geographic location associated with the event |
| **Port** | TCP port used during communication |
| **Protocol** | Protocol used during the communication |
| **Query** | String used to run the query |
| **QueryTarget** | User, group, domain, or any other entity being queried |
| **QueryType** | Type of the query |
| **ReportId** | Unique identifier for the event |
| **TargetAccountDisplayName** | Display name of the account that the recorded action was applied to |
| **TargetAccountUpn** | User principal name (UPN) of the account that the recorded action was applied to |
| **TargetDeviceName** | Fully qualified domain name (FQDN) of the device that the recorded action was applied to |
| **Timestamp** | Date and time when the record was generated |

### ActionTypes:
| ActionType | Description |
| --- | --- |
| **DNS query** | Type of query user performed against the domain controller (AXFR, TXT, MX, NS, SRV, ANY, DNSKEY) |
| **LDAP query** | An LDAP query was performed. |
| **LdapQuery** | An LDAP query was performed. |
| **SAMR query** | A SAMR query was performed. |

### Examples:

### Find use of net.exe to send SAMR queries to Active Directory
```
// Find processes that sent SAMR queries to Active Directory
IdentityQueryEvents
| where Timestamp > ago(3d)
| where ActionType == "SAMR query" 
//    and isnotempty(AccountName)
| project QueryTime = Timestamp, DeviceName, AccountName, Query, QueryTarget 
| join kind=inner (
DeviceProcessEvents 
| where Timestamp > ago(3d)
| extend DeviceName = toupper(trim(@"\..*$",DeviceName))
//| where InitiatingProcessCommandLine contains "net.exe"
| project ProcessCreationTime = Timestamp, DeviceName, AccountName,
     InitiatingProcessFileName , InitiatingProcessCommandLine
    ) on DeviceName//, AccountName
| where ProcessCreationTime - QueryTime between (-2m .. 2m)
| project QueryTime, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, Query, QueryTarget //,AccountName
```


## Table: UrlClickEvents

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-urlclickevents-table?view=o365-worldwide)
**Description:** Events involving URLs clicked, selected, or requested on Microsoft Defender for Office 365

### Table Schema:
| Field | Description |
| --- | --- |
| **AccountUpn** | User principal name (UPN) of the account |
| **ActionType** | Type of activity that triggered the event |
| **DetectionMethods** | Methods used to detect whether the URL contains or leads to malware, phishing, or other threats |
| **IPAddress** | IP address assigned to the device during communication |
| **IsClickedThrough** | Indicates whether the user was able to click through to the original URL or not |
| **NetworkMessageId** | Unique identifier for the email from which the URL was clicked |
| **ReportId** | Unique identifier for the event |
| **ThreatTypes** | Verdict on whether the URL leads to malware, phishing, or other threats |
| **Timestamp** | Date and time when the record was generated |
| **Url** | URL that was clicked |
| **UrlChain** | List of URLs in the redirection chain |
| **Workload** | Information about the workload from which the URL originated from |

### ActionTypes:
| ActionType | Description |
| --- | --- |
| **ClickAllowed** | The user was allowed to navigate to the URL. |
| **ClickBlocked** | The user was blocked from navigating to the URL. |
| **ClickBlockedByTenantPolicy** | The user was blocked from navigating to the URL by a tenant policy. |
| **UrlErrorPage** | The URL the user clicked showed an error page. |
| **UrlScanInProgress** | The URL the user clicked is being scanned by Safe Links. |
