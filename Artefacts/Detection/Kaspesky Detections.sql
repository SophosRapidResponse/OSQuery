/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| The query searches in the Kaspersky event logs "Kaspersky Endpoint Security"   |
| the IDs: 302, 303 and 331 that identifies malicious objects/software that can  |
| be used by TAs during an intrusion                                             |
|                                                                                |
| REFERENCE:                                                                     |
| https://support.kaspersky.com/KESWin/11.6.0/en-US/209858.htm                   |
|                                                                                |
| Version: 1.0                                                                   |
| Author: The rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/


SELECT
    strftime('%Y-%m-%dT%H:%M:%SZ',datetime) AS Datetime,
    source AS Source,
    provider_name AS Provider_Name,
    eventid AS Event_ID,
    CASE WHEN eventid = '302' THEN 'Malicious object detected'
    WHEN eventid = '303' THEN 'Detected legitimate software that can be used by intruders to damage your computer or personal data'
    WHEN eventid = '331' THEN 'Blocked'
    END AS Description,
    data AS Data,
    'EVTX' AS Data_Source,
    'Kaspersky Detections' AS Query 
FROM sophos_windows_events 
WHERE source = 'Kaspersky Endpoint Security'
    AND eventid IN ('302', '303', '331')
ORDER BY Datetime DESC

