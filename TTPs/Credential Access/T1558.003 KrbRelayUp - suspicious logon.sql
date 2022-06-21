/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                     |
| The query detects suspicious local successful logon event which has similarities|
| with the events created during Kerberos relay attack variant                    |
|                                                                                 |
| Reference:                                                                      |
| https://github.com/Dec0ne/KrbRelayUp                                            |
| https://github.com/cube0x0/KrbRelay                                             |
|                                                                                 |
| Version: 1.0                                                                    |
| Author: The Rapid Response Team | Lee Kirkpatrick                               |
| github.com/SophosRapidResponse                                                  |
\********************************************************************************/

SELECT
    strftime('%Y-%m-%dT%H:%M:%SZ',datetime) AS datetime, 
    source,
    provider_name,
    eventid,
    JSON_EXTRACT(data, '$.EventData.AuthenticationPackageName') AS AuthenticationPackageName,
   JSON_EXTRACT(data, '$.EventData.LogonType') AS LogonType,
    JSON_EXTRACT(data, '$.EventData.IpAddress') AS SourceIP,
    JSON_EXTRACT(data, '$.EventData.TargetUserSid') AS TargetUserSid,
    'EVTX' AS Data_Source,
    'T1558.003 - KrbRelayUp suspicious logon' AS Query 
FROM sophos_windows_events
WHERE source = 'Security' 
    AND eventid = 4624
    AND AuthenticationPackageName = 'Kerberos' 
    AND LogonType = '3'
    AND SourceIP = '127.0.0.1'
    AND TargetUserSid LIKE 'S-1-5-21-%-500'

