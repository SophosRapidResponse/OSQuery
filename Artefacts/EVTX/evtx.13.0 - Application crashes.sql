/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Lists applications that have crashed, stopped responding, or been added to the |
| WER app crash report in the Application Event Log EID 1000 to 1002.            |
| TACTIC: Execution                                                              |
|                                                                                |
| Version: 1.1                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT DISTINCT
CAST(strftime('%Y-%m-%dT%H:%M:%SZ',datetime) AS TEXT) AS date_time,
CAST(source AS TEXT) AS source,
provider_name,
eventid,
CASE 
    WHEN eventid = 1000 THEN 'Application Error'
    WHEN eventid = 1002 THEN 'Application Hang'
    WHEN eventid = 1001 THEN 'WER Application Crashes Reports'
END AS details,
CASE
    WHEN eventid = 1001 THEN regex_match(regex_split(JSON_EXTRACT(data,'$.EventData.Data'),',',5),'(.*\.exe|.*\.dll)',0)
    WHEN eventid = 1000 THEN regex_split(JSON_EXTRACT(data,'$.EventData.Data'),',',0) 
    WHEN eventid = 1002 THEN regex_split(JSON_EXTRACT(data,'$.EventData.Data'),',',0) 
END AS application,
CASE
    WHEN eventid = 1000 THEN regex_split(JSON_EXTRACT(data,'$.EventData.Data'),',',10) 
    WHEN eventid = 1002 THEN regex_split(JSON_EXTRACT(data,'$.EventData.Data'),',',5)
    WHEN eventid = 1001 THEN regex_match(data,'C:\\.*.+(,.+)$',0)
END AS path,
data AS raw,
'EVTX.13.0' AS query
FROM sophos_windows_events
WHERE source = 'Application' 
    AND (provider_name IN ('Application Error','Application Hang') AND eventid IN ('1000','1002')
    OR provider_name = 'Windows Error Reporting' AND eventid = 1001)
AND application != ''
AND time >= $$start_time$$
AND time <= $$end_time$$
ORDER BY datetime DESC