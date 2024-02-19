/*************************** Sophos.com/RapidResponse ***************************\
|                                                                                |
| DESCRIPTION                                                                    |
| Looking for new suspicious HealthMailbox accounts.                             |
|                                                                                |
| Version: 1.0                                                                   |
| Author: @AltShiftPrtScn                                                        |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

WITH Event_Data(Event_id, time, Data) AS (
SELECT eventid, time, JSON_EXTRACT(swe.data, '$.EventData.Data') AS Data
FROM sophos_windows_events swe
WHERE source = 'MSExchange Management' AND data LIKE '%New-Mailbox,%' AND data LIKE '%HealthMailbox%'
)

SELECT
STRFTIME('%Y-%m-%dT%H:%M:%SZ', DATETIME(time, 'unixepoch')) AS Datetime,
SPLIT(Data,'"',1) AS Username,
Data AS Data,
'MSExchange Management EVTX' AS Data_Source,
'ProxyShell.05.0' AS Query
FROM Event_Data