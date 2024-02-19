/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Lists all successful authentications EID 302 from the Remote Desktop (RDP)     |
| gateway event logs TerminalServices-Gateway/Operational.                       |
|                                                                                |
| Should be run on servers that have RD Gateway service installed. Returns user  |
| information, device information, and connection details.                       |
|                                                                                |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
strftime('%Y-%m-%dT%H:%M:%SZ',datetime) AS date_time,
eventid,
CASE 
    WHEN eventid = 302 THEN 'Connected'
    WHEN eventid = 303 THEN 'Disconnected'
END AS status,
JSON_EXTRACT(data,'$.UserData.ConnectionProtocol') AS protocol,
JSON_EXTRACT(data,'$.UserData.IpAddress') AS ip_address,
JSON_EXTRACT(data,'$.UserData.Username') AS user_name,
JSON_EXTRACT(data,'$.UserData.Resource') AS device_name,
JSON_EXTRACT(data,'$.UserData.AuthType') AS auth_type,
JSON_EXTRACT(data,'$.UserData.ErrorCode') AS error_code,
JSON_EXTRACT(data,'$.UserData.EventInfo') AS event_info,
JSON_EXTRACT(data,'$.UserData.BytesReceived') AS bytes_received,
JSON_EXTRACT(data,'$.UserData.BytesTransfered') AS bytes_transfered,
JSON_EXTRACT(data,'$.UserData.SessionDuration') AS session_duration,
'TS Gateway EVTX' AS data_source,
'Logins.05.0' AS query
FROM sophos_windows_events
WHERE source = 'Microsoft-Windows-TerminalServices-Gateway/Operational'
    AND eventid IN (302,303)
