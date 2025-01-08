/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Gets all event from the Kaspersky Endpoint Security logs, focusing on Event    |
| IDs 302, 303, and 332, which indicate malicious objects and applications       |
| detected on the device.                                                        |
|                                                                                |
| REFERENCE:                                                                     |
| https://support.kaspersky.com/KESWin/11.6.0/en-US/209858.htm                   |
|                                                                                |
| Query Type: Endpoint                                                           |
| Version: 1.0                                                                   |
| Author: The rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/


SELECT
strftime('%Y-%m-%dT%H:%M:%SZ',datetime) AS date_time,
source,
provider_name,
eventid,
CASE
    WHEN eventid = '302' THEN 'Malicious object detected'
    WHEN eventid = '303' THEN 'Detected legitimate software that can be used by intruders to damage your computer or personal data'
    WHEN eventid = '331' THEN 'Blocked'
END AS description,
data AS raw,
'EVTX' AS data_source,
'detection.03.0' AS query 
FROM sophos_windows_events 
WHERE source = 'Kaspersky Endpoint Security'
    AND eventid IN ('302', '303', '331')
    AND time > 0
ORDER BY datetime DESC

