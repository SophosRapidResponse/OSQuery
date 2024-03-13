/****************************** Sophos.com/RapidResponse ******************************\
| DESCRIPTION                                                                          |
| Detects the possible source machine and username associated with a PsExec remote     |
| execution by looking at the System event logs EID 7045 when the service PsExeSVC was |
| created and correlating with a Security event ID 4624 Logon Type 3 around the time of|
| the service creation (10 seconds before)                                             |
|                                                                                      |
| IMPORTANT                                                                            |
| Windows overwrites the Security event logs as needed (oldest first). Therefore, the  |
| query might not bring any results if the logs has rolled                             |
|                                                                                      |
| Query Type: Endpoint                                                                 |
| Author: The Rapid Response Team | Lee Kirkpatrick                                    |
| github.com/SophosRapidResponse                                                       |
\**************************************************************************************/

With PsExec AS (
SELECT
    strftime('%Y-%m-%dT%H:%M:%SZ',sophos_windows_events.datetime) as datetime,
    time,
    time - 10 as TimeDiff,
    JSON_EXTRACT(data, '$.EventData.ServiceName') AS ServiceName,
    JSON_EXTRACT(data, '$.EventData.ImagePath') AS ImagePath
FROM sophos_windows_events
WHERE source = 'System'
    AND eventid = 7045
    AND (LOWER(ServiceName) LIKE '%psexe%' OR LOWER(ImagePath) LIKE '%psexe%')
    AND time > 0
)

SELECT
    DISTINCT(strftime('%Y-%m-%dT%H:%M:%SZ',sophos_windows_events.datetime)) AS Logon_Time,
    JSON_EXTRACT(sophos_windows_events.data, '$.EventData.TargetUserName') AS Username,
    sophos_windows_events.eventid AS Event_ID,
    JSON_EXTRACT(sophos_windows_events.data, '$.EventData.LogonType') AS Logon_Type,
    JSON_EXTRACT(sophos_windows_events.data, '$.EventData.IpAddress') AS Source_IP,
    JSON_EXTRACT(sophos_windows_events.data, '$.EventData.TargetUserSid') AS User_SID,
    PsExec.datetime AS PsExec_Time,
    PsExec.ServiceName,
    PsExec.ImagePath,
    'EVTX' AS Data_Source,
    'Remote Execution PsExec'AS Query
FROM sophos_windows_events, PsExec
WHERE sophos_windows_events.source = 'Security'
    AND sophos_windows_events.eventid = '4624' 
    AND Logon_Type = '3'
    AND (sophos_windows_events.time >= PsExec.TimeDiff AND sophos_windows_events.time <= PsExec.time)
    AND Source_IP != ''