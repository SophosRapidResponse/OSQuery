/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| List all successful authentication logs (EID 302) from the Remote Desktop (RD) |
| Gateway event logs: Microsoft-Windows-TerminalServices-Gateway/Operational.    |
|                                                                                |
| Should be run on servers that have the Remote Desktop Gateway service installed|
| The query returns user information, device information, and connection details |
|                                                                                |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
strftime('%Y-%m-%dT%H:%M:%SZ',datetime) AS date_time,
eventid,
JSON_EXTRACT(data,'$.UserData.ConnectionProtocol') AS protocol,
JSON_EXTRACT(data,'$.UserData.IpAddress') AS ip_address,
JSON_EXTRACT(data,'$.UserData.Username') AS user_name,
JSON_EXTRACT(data,'$.UserData.Resource') AS device_name,
JSON_EXTRACT(data,'$.UserData.AuthType') AS auth_type,
JSON_EXTRACT(data,'$.UserData.ErrorCode') AS error_code,
JSON_EXTRACT(data,'$.UserData.EventInfo') AS event_info,
'TS Gateway EVTX' AS data_source,
'Logins.05.0' AS query
FROM sophos_windows_events
WHERE source = 'Microsoft-Windows-TerminalServices-Gateway/Operational'
    AND eventid = 302
