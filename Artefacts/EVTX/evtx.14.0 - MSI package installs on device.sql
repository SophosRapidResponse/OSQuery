/*************************** Sophos.com/RapidResponse ****************************\
| DESCRIPTION                                                                     |
| Gets all MSI packages installed on a device by querying event IDs 1040          |
| (installer started) and 1033 (application installed) from the Application event |
| log.                                                                            |
|                                                                                 |
| Query Type: Endpoint                                                            |
| Version: 1.0                                                                    |
| Author: The Rapid Response Team                                                 |
| github.com/SophosRapidResponse                                                  |
\*********************************************************************************/


SELECT DISTINCT
strftime('%Y-%m-%dT%H:%M:%SZ', swe.datetime) AS date_time,
swe.source,
swe.provider_name,
swe.eventid,
CASE 
    WHEN swe.eventid = 1033 THEN 'package installed'
    WHEN swe.eventid = 1040 THEN 'installer started'
END AS event_id,
CASE 
    WHEN swe.eventid = 1040 THEN SUBSTR(
        JSON_EXTRACT(swe.data, '$.EventData.Data'), 
        0, 
        INSTR(JSON_EXTRACT(swe.data, '$.EventData.Data'), ',')
    )
    ELSE NULL 
END AS msi_installer,
CASE 
    WHEN swe.eventid = 1040 THEN '' 
    ELSE JSON_EXTRACT(swe.data, '$.EventData.Data') 
END AS product_details,
swe.user_id AS sid,
u.username,
hash.sha256,
auth.subject_name,
'EVTX' AS data_source,
'EVTX.14.0' AS query
FROM sophos_windows_events swe
LEFT JOIN users u ON swe.user_id = u.uuid
LEFT JOIN hash ON hash.path = msi_installer
LEFT JOIN authenticode auth ON auth.path = msi_installer
WHERE swe.source = 'Application' 
    AND swe.provider_name = 'MsiInstaller' 
    AND swe.eventid IN ('1033', '1040')
    AND swe.time > 0
ORDER BY swe.time DESC
