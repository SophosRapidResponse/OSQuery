/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Lists all events from the event log Microsoft-Windows-Bits-Client/Operational  |
| Due to the high amount of events, the query focus on the event ID 59 which     |
| provides information about the URL that the BITS JOB connected to              |
|                                                                                |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT 
    strftime('%Y-%m-%dT%H:%M:%SZ',datetime) AS date_time, 
    source,
    eventid,
    JSON_EXTRACT(data, '$.EventData.name') As job_title,
    JSON_EXTRACT(data, '$.EventData.url') As URL,
    JSON_EXTRACT(data, '$.EventData.bytesTotal') As bytes_total,
    JSON_EXTRACT(data, '$.EventData.fileLength') As file_length,
    JSON_EXTRACT(data, '$.EventData.fileTime') As file_time,
    'EVTX' AS Data_Source,
    'BITS Jobs in EVTX' AS Query
FROM sophos_windows_events 
WHERE source ='Microsoft-Windows-Bits-Client/Operational' 
    AND eventid = '59'
GROUP BY job_title
ORDER BY date_time DESC