/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Hunts for potential DCSync attacks. Lists EID 4662 that uses the access mask   |
| 0x100 (Control Access) and contain properties that represent each of the       |
| functions associated with the replication attempt. TACTIC: Credential Access   |
|                                                                                |
| The DCSync attack simulates the behavior of a Domain Controller and asks other |
| Domain Controllers to replicate information using the Directory Replication    |
| Service Remote Protocol (MS-DRSR).                                             |
|                                                                                |
| Adversaries can use the DCSync technique to compromise major credentials such  |
| as the Kerberos krbtgt keys used legitimately for tickets creation. This attack|
| requires some extended privileges to succeed (DS-Replication-Get-Changes and   |
| DS-Replication-Get-Changes-All), which are granted by default to members of the|
| Administrators, Domain Admins, Enterprise Admins,and Domain Controllers groups.|
| Privileged accounts can be abused to grant controlled objects the right to     |
| DCsync/Replicate.                                                              |
|                                                                                |
| Possible investigation steps                                                   |
| - Identify the user account that performed the action                          |
| - Contact the account and system owners to validate the activity               |
| - Investigate other alerts associated with the user/host recently              |
| - Correlate events 4662 and 4624 (Logon Type 3) on the DC that received the    |
| replication request to check if the request came from other DC or not          |
|                                                                                |
| Query Type: Endpoint                                                           |
| Version: 1.0                                                                   |
| Author: The rapid response team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

WITH dcsyn AS (
SELECT
strftime('%Y-%m-%d', datetime) AS date,
eventid,
datetime,
JSON_EXTRACT(data, '$.EventData.SubjectDomainName') AS subject_domain_name,
JSON_EXTRACT(data, '$.EventData.SubjectUserName') AS subject_username,
JSON_EXTRACT(data, '$.EventData.SubjectUserSid') AS subject_sid,
JSON_EXTRACT(data, '$.EventData.AccessMaks') AS access_mask,
JSON_EXTRACT(data, '$.EventData.AccessList') AS access_list,
JSON_EXTRACT(data, '$.EventData.ObjectName') AS object_name,
JSON_EXTRACT(data, '$.EventData.ObjectType') AS object_type,
JSON_EXTRACT(data, '$.EventData.Properties') AS properties,
data
FROM sophos_windows_events
WHERE source = 'Security'
    AND eventid = 4662
    AND provider_name = 'Microsoft-Windows-Security-Auditing'
    AND subject_username NOT LIKE '%$'
    AND JSON_EXTRACT(data, '$.EventData.ObjectType') = '%{19195a5b-6da0-11d0-afd3-00c04fd930c9}'
    AND (
            JSON_EXTRACT(data, '$.EventData.Properties') LIKE '%1131f6aa-9c07-11d1-f79f-00c04fc2dcd2%'
            OR JSON_EXTRACT(data, '$.EventData.Properties') LIKE '%1131f6ad-9c07-11d1-f79f-00c04fc2dcd2%'
            OR JSON_EXTRACT(data, '$.EventData.Properties') LIKE '%9923a32a-3607-11d2-b9be-0000f87a36b2%'
            OR JSON_EXTRACT(data, '$.EventData.Properties') LIKE '%Replicating Directory Changes all%'
        )
    AND time > 0
)

SELECT 
date, 
eventid,
subject_domain_name,
subject_username,
subject_sid,
access_mask,
access_list,
object_name,
object_type,
properties,
COUNT(*) AS event_count,
CAST (MIN(datetime) AS TEXT) AS first_occurrance,
CAST (MAX(datetime) AS TEXT) AS last_occurrance,
data AS raw,
'Security' AS data_source,
'evtx.03.0' AS query
FROM dcsyn
GROUP BY date, subject_username