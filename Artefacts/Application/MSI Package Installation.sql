/*************************** Sophos.com/RapidResponse ****************************\
| DESCRIPTION                                                                     |
| Lists all MSI packages that were installed on a device.                         |
| MSI package can be installed using either msiexec.exe or the Windows GUI.       |
| The query gets all occurrences of the event id 1040 (Installer Started) and the |
| event id 1033 (application installed)  from the Application Event Log           |
|                                                                                 |
|                                                                                 |
| Version: 1.0                                                                    |
| Author: The Rapid Response Team                                                 |
| github.com/SophosRapidResponse                                                  |
\*********************************************************************************/


SELECT DISTINCT
    strftime('%Y-%m-%dT%H:%M:%SZ',swe.datetime) AS date_time, 
    swe.source,
    swe.provider_name,
    CASE WHEN swe.eventid = 1033 THEN swe.eventid || ' - installed'
    WHEN swe.eventid = 1040 THEN swe.eventid || ' - installer started'
    END AS event_id,
    CASE WHEN swe.eventid = 1040 THEN regex_split(JSON_EXTRACT(swe.data,'$.EventData.Data'),',',0) ELSE '-' END AS msi_installer,
    CASE WHEN swe.eventid = 1040 THEN '' ELSE JSON_EXTRACT(swe.data,'$.EventData.Data') END AS product_details,
    swe.user_id AS sid, 
    u.username,
    hash.sha256,
    auth.subject_name,
    swe.data as raw,
    'MSI Package Installation' As query,
    'EVTX' AS data_source
FROM sophos_windows_events swe
LEFT JOIN users u ON swe.user_id = u.uuid
LEFT JOIN hash ON hash.path = msi_installer
LEFT JOIN authenticode auth ON auth.path = msi_installer
WHERE swe.source = 'Application' 
    AND swe.provider_name = 'MsiInstaller' 
    AND swe.eventid IN ('1033','1040')
GROUP BY swe.datetime, msi_installer
ORDER BY swe.datetime DESC