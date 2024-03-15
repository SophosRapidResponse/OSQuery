/******************************* Sophos.com/RapidResponse ********************************\
| DESCRIPTION                                                                             |
| Retrieves all EID: 5136 in the Windows Security event logs, aiming to identify potential|
| webshells possibly linked to the exploitation of CVE-2021-27065.                        |
| Looks for changes in the InternalHostName or ExternalHostName properties of Exchange    |
| OAB Virtual Directory objects in AD Directory Services where the new objects contain    |
| potential webshell                                                                      |
|                                                                                         |
| REFERENCE                                                                               |
| CVE-2021-27065                                                                          |
| https://github.com/Azure/Azure-Sentinel/blob/master/Detections/SecurityEvent/           |
| ExchangeOABVirtualDirectoryAttributeContainingPotentialWebshell.yaml                    |
| https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5136|
|                                                                                         |
| Query Type: Endpoint                                                                    |
| Author: The Rapid Response Team                                                         |
| github.com/SophosRapidResponse                                                          |
\*****************************************************************************************/

SELECT
    strftime('%Y-%m-%dT%H:%M:%SZ',datetime) AS event_time,
    source,
    provider_name,
    eventid,
    JSON_EXTRACT(data, '$.EventData.SubjectUserName') AS username,
    JSON_EXTRACT(data, '$.EventData.SubjectUserSid') AS user_sid,
    JSON_EXTRACT(data, '$.EventData.SubjectDomainName') AS domain,
    JSON_EXTRACT(data, '$.EventData.ObjectClass') AS Object_Class,
    JSON_EXTRACT(data, '$.EventData.ObjectDN') AS Object_DN,
    JSON_EXTRACT(data, '$.EventData.ObjectGUID') AS Object_GUID,
    JSON_EXTRACT(data, '$.EventData.AttributeLDAPDisplayName') AS Attribute_LDAP_Name,
    JSON_EXTRACT(data, '$.EventData.AttributeValue') AS Attribute_Value,
    JSON_EXTRACT(data, '$.EventData.OperationType') AS Operation_type,
    data AS raw_Data,
    'EVTX' AS source,
    'Exchange OAB Virtual Directory Containting Webshell' AS Query
FROM sophos_windows_events
WHERE eventid = '5136' 
AND source = 'Security'
AND JSON_EXTRACT(data, '$.EventData.ObjectClass') LIKE '%msExchOABVirtualDirectory%'
AND JSON_EXTRACT(data, '$.EventData.AttributeLDAPDisplayName') IN ('msExchExternalHostName', 'msExchInternalHostName')
AND JSON_EXTRACT(data, '$.EventData.AttributeValue') LIKE '%script%'
AND time > 0
ORDER BY datetime DESC