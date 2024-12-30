/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Use this query to search for a hostname, IP, username, or unique string across |
| multiple EVTX logs. It returns raw data for any references found.              |
|                                                                                |
| VARIABLES                                                                      |
| value(string) - the string you are looking for                                 |
|                                                                                |
| Query Type: Endpoint                                                           |
| Version: 1.0                                                                   |
| Author: @AltShiftPrtScn & Bill Kearney                                         |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
strftime('%Y-%m-%dT%H:%M:%SZ',swe.datetime) AS Datetime, 
source AS Source,
provider_name AS Provider_Name,
eventid AS Event_ID,
user_id AS SID,
data AS Data,
'EVTX Logs' AS Data_Source,
'EVTX.01.0' AS Query 
FROM sophos_windows_events swe
WHERE data like '%$$value$$%'
AND (
source LIKE 'System' OR
source LIKE 'Application' OR
source LIKE 'Security' OR
source LIKE 'Setup' OR
source LIKE 'Microsoft-Windows-PowerShell/Operational' OR
source LIKE 'Windows PowerShell' OR
source LIKE 'Microsoft-Windows-TaskScheduler/Operational' OR
source LIKE 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' OR
source LIKE 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' OR
source LIKE 'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational' OR
source LIKE 'Microsoft-Windows-TerminalServices-Printers/Operational' OR
source LIKE 'OAlerts')
AND time > 0