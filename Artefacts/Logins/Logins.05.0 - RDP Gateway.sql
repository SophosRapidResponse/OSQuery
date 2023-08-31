/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Gets logs from successful authentications (EID 302) from the Remote Desktop    |
| Gateway (RD Gateway) event logs.                                               |
|                                                                                |
| The query provides user information, device information, and connection details|
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
JSON_EXTRACT(data,'$.UserData.Username') AS user,
JSON_EXTRACT(data,'$.UserData.Resource') AS device_name,
JSON_EXTRACT(data,'$.UserData.AuthType') AS auth_type,
JSON_EXTRACT(data,'$.UserData.ErrorCode') AS error_code,
JSON_EXTRACT(data,'$.UserData.EventInfo') AS event_info,
source,
'RDP Gateway' AS query
FROM sophos_windows_events
WHERE source = 'Microsoft-Windows-TerminalServices-Gateway/Operational'
    AND eventid = 302
