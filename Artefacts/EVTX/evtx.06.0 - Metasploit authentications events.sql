/****************************** Sophos.com/RapidResponse ******************************\
| DESCRIPTION                                                                           |
| Searches the Security event logs for events related to Metasploit host authentication.|
|                                                                                       |
| REFERENCE:                                                                            |
| https://github.com/rapid7/metasploit-framework/blob/master/lib/rex/proto/smb/client.rb|
|                                                                                       |
| Query Type: Endpoint                                                                  |
| Version: 1.0                                                                          |
| Author: The Rapid Response Team | Lee Kikpatrick                                      |
| github.com/SophosRapidResponse                                                        |
\***************************************************************************************/

SELECT
strftime('%Y-%m-%dT%H:%M:%SZ',datetime) AS Datetime,
source,
provider_name,
eventid AS EventID,
CASE WHEN eventid = 4624 THEN JSON_EXTRACT(data, '$.EventData.WorkstationName')
WHEN eventid = 4625 THEN JSON_EXTRACT(data, '$.EventData.WorkstationName')
WHEN eventid = 4776 THEN JSON_EXTRACT(data, '$.EventData.Workstation') 
END AS Workstation,
JSON_EXTRACT(data, '$.EventData.IpAddress') AS Source_IP,
JSON_EXTRACT(data, '$.EventData.Status') AS Status,
JSON_EXTRACT(data, '$.EventData.TargetUserName') AS TargetUserName,
JSON_EXTRACT(data, '$.EventData.PackageName') As PackageName,
JSON_EXTRACT(data, '$.EventData.LogonType') AS Logon_Type,
JSON_EXTRACT(data, '$.EventData.TargetUserSid') AS User_SID,
JSON_EXTRACT(data, '$.EventData.AuthenticationPackageName') As AuthenticationPackageName,
'EVTX' AS Data_Source,
'EVTX.06.0' AS Query
FROM sophos_windows_events 
WHERE source = 'Security'
    AND (eventid IN (4624,4625) AND regex_match(JSON_EXTRACT(data, '$.EventData.WorkstationName'),'^[A-Za-z0-9]{16}$', 0) AND AuthenticationPackageName = 'NTLM')
    OR (eventid = 4776 AND regex_match(JSON_EXTRACT(data, '$.EventData.Workstation'),'^[A-Za-z0-9]{16}$', 0))
    AND time > 0
