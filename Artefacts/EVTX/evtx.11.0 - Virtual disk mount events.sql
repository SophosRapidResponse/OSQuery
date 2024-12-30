/**************************** Sophos.com/RapidResponse ****************************\
| DESCRIPTION                                                                      |
| Searches the Windows VHDMP/Operational log for information on mounted container  |
| files in event ID 12. Container file extensions include .iso, .vhd, .vhdx, .img, |
| and others.                                                                      |
|                                                                                  |
| The events can be FP on servers but suspicious on workstations                   |
|                                                                                  |
| Query Type: Endpoint                                                             |
| Version: 1.0                                                                     |
| Author: The Rapid Response Team | Lee Kikpatrick                                 |
| github.com/SophosRapidResponse                                                   |
\**********************************************************************************/

SELECT DISTINCT
strftime('%Y-%m-%dT%H:%M:%SZ',datetime) AS date_time,
eventid,
'Mounted device' AS details,
CASE 
	WHEN JSON_EXTRACT(data, '$.EventData.VhdFile') LIKE '\\?\%' THEN SUBSTR(JSON_EXTRACT(data, '$.EventData.VhdFile'), 5)
	ELSE JSON_EXTRACT(data, '$.EventData.VhdFile')
END AS path,
regex_match(JSON_EXTRACT(data, '$.EventData.VhdFile'),'([^\\]+)\.*$',0) AS filename,
source,
'EVTX' AS Data_Source,
'EVTX.11.0' AS Query 
FROM sophos_windows_events
WHERE source = 'Microsoft-Windows-VHDMP-Operational' 
AND eventid = 12
AND time > 0
GROUP BY path
ORDER BY time DESC