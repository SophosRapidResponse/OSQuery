/*************************** Sophos.com/RapidResponse ****************************\
| DESCRIPTION                                                                     |
| Lists all MSI packages that were installed on a device. Gets all occurrences of |
| EID 1040 (Installer started) and EID 1033 (Application installed) in the        |
| Application Event Log.                                                          |
|                                                                                 |
| Query Type: Endpoint                                                            |
| Version: 1.0                                                                    |
| Author: The Rapid Response Team                                                 |
| github.com/SophosRapidResponse                                                  |
\*********************************************************************************/


SELECT DISTINCT
strftime('%Y-%m-%dT%H:%M:%SZ',swe.datetime) AS date_time, 
swe.source,
swe.provider_name,
CASE 
    WHEN swe.eventid = 1033 THEN swe.eventid || ' - installed'
    WHEN swe.eventid = 1040 THEN swe.eventid || ' - installer started'
END AS event_id,
CASE 
    WHEN swe.eventid = 1040 THEN regex_split(JSON_EXTRACT(swe.data,'$.EventData.Data'),',',0) 
    ELSE NULL 
END AS msi_installer,
CASE 
    WHEN swe.eventid = 1040 THEN '' 
ELSE JSON_EXTRACT(swe.data,'$.EventData.Data') END AS product_details,
swe.user_id AS sid, 
u.username,
hash.sha256,
auth.subject_name,
'EVTX.14.0' As query
FROM sophos_windows_events swe
LEFT JOIN users u ON swe.user_id = u.uuid
LEFT JOIN hash ON hash.path = msi_installer
LEFT JOIN authenticode auth ON auth.path = msi_installer
WHERE swe.source = 'Application' 
    AND swe.provider_name = 'MsiInstaller' 
    AND swe.eventid IN ('1033','1040')
    AND swe.time > 0
GROUP BY swe.datetime, msi_installer
ORDER BY swe.datetime DESC