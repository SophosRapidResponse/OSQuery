/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Looks for EID 104 events in Windows-RemoteDesktopService-RDPCoreTS/Operational,|
| which show the time bias of the client connecting. The time bias is the        |
| difference between the local time zone and UTC. A login with a different time  |
| zone from the customer maybe suspicious. Run the RDP logins query to find the  |
| user that logged in around that time.                                          |
|                                                                                |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT 
strftime('%Y-%m-%dT%H:%M:%SZ',datetime) AS date_time, 
eventid,  
JSON_EXTRACT(data, '$.EventData.TimezoneBiasHour') AS timezone_bias_hour,  
'RdpCoreTS/Operational' AS data_source,
'Logins.07.0' AS query 
FROM sophos_windows_events  
WHERE source = 'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational' 
    AND eventid IN (104)