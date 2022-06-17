/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| The query search for suspicious use of bitsadmin jobs by looking at the Windows|
| event log: BITS-Client/Operational. Due to the high amount of events, the query|
| focus on the event ID 59 which provides information about the URL that the     |
| BitsAdmin job is connected to.                                                 |
|                                                                                |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT 
strftime('%Y-%m-%dT%H:%M:%SZ',datetime) AS Datetime, 
source AS Source,
provider_name AS Provider_Name,
eventid AS Event_ID,
JSON_EXTRACT(data, '$.EventData.name') As JobTitle,
JSON_EXTRACT(data, '$.EventData.url') As URL,
JSON_EXTRACT(data, '$.EventData.bytesTotal') As bytesTotal,
JSON_EXTRACT(data, '$.EventData.fileLength') As fileLength,
JSON_EXTRACT(data, '$.EventData.fileTime') As fileTime,
'EVTX' AS Data_Source,
'T1197 - BITS Jobs in EVTX' AS Query
FROM sophos_windows_events 
WHERE source ='Microsoft-Windows-Bits-Client/Operational' 
AND Event_ID = '59'
group by JobTitle