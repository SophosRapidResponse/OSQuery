/****************************** Sophos.com/RapidResponse ******************************\
| DESCRIPTION                                                                          |
| Detects the potential source device and username associated with a PsExec remote     |
| execution by searching the System event logs for event ID 7045 (service PsExeSVC     |
| creation) and correlating with Security event ID 4624 (Logon Type 3) within 10       |
| seconds of the service creation.                                                     |
|                                                                                      |
| IMPORTANT                                                                            |
| Windows overwrites the Security event logs as needed (oldest first). Therefore, the  |
| query might not bring any results if the logs has rolled                             |
|                                                                                      |
| Query Type: Endpoint                                                                 |
| Author: The Rapid Response Team | Lee Kirkpatrick                                    |
| github.com/SophosRapidResponse                                                       |
\**************************************************************************************/

WITH PsExec AS (
    SELECT
    strftime('%Y-%m-%dT%H:%M:%SZ', swe.datetime) AS datetime,
    swe.time,
    swe.time - 10 AS TimeDiff,
    JSON_EXTRACT(swe.data, '$.EventData.ServiceName') AS ServiceName,
    JSON_EXTRACT(swe.data, '$.EventData.ImagePath') AS ImagePath
    FROM sophos_windows_events swe
    WHERE swe.source = 'System'
        AND swe.eventid = 7045
        AND (LOWER(JSON_EXTRACT(swe.data, '$.EventData.ServiceName')) LIKE '%psexe%' 
             OR LOWER(JSON_EXTRACT(swe.data, '$.EventData.ImagePath')) LIKE '%psexe%')
        AND swe.time > 0
)

SELECT
strftime('%Y-%m-%dT%H:%M:%SZ', swe.datetime) AS Logon_Time,
JSON_EXTRACT(swe.data, '$.EventData.TargetUserName') AS Username,
swe.eventid AS Event_ID,
JSON_EXTRACT(swe.data, '$.EventData.LogonType') AS Logon_Type,
JSON_EXTRACT(swe.data, '$.EventData.IpAddress') AS Source_IP,
JSON_EXTRACT(swe.data, '$.EventData.TargetUserSid') AS User_SID,
PsExec.datetime AS PsExec_Time,
PsExec.ServiceName,
PsExec.ImagePath,
'EVTX' AS Data_Source,
'Remote Execution PsExec' AS Query
FROM sophos_windows_events swe
JOIN PsExec ON swe.time >= PsExec.TimeDiff AND swe.time <= PsExec.time
WHERE swe.source = 'Security'
    AND swe.eventid = 4624
    AND JSON_EXTRACT(swe.data, '$.EventData.LogonType') = '3'
    AND JSON_EXTRACT(swe.data, '$.EventData.IpAddress') != ''
ORDER BY swe.time DESC;
