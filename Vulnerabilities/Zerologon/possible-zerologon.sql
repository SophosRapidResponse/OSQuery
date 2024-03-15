/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Detects possible Zerologon exploitation listed as CVE-2020-1472.               |
|                                                                                |
| Query Type: Endpoint                                                           |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team | Lee Kirkpatrick                              |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/


SELECT
   datetime,
   eventid,
data
FROM sophos_windows_events
WHERE source = 'System'
   AND eventid IN('5805','5723')
   AND 
   (
   data LIKE '%kali%'
   OR data LIKE '%mimikatz%'
   )
   AND time > 0