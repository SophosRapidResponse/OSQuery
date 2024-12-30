/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Lists all scheduled tasks events in the Windows Task Scheduler event logs      |
| during a selected timeframe.                                                   |
|                                                                                |
| VARIABLES                                                                      |
| - start_time (type: DATE)                                                      |
| - end_time (type: DATE)                                                        |
|                                                                                |
| Query Type: Endpoint                                                           |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT DISTINCT
    strftime('%Y-%m-%dT%H:%M:%SZ',datetime) AS date_time, 
    source,
    eventid,
    CASE WHEN eventid = 106 THEN 'Scheduled task created'
    WHEN eventid = 140 THEN 'Scheduled task updated'
    WHEN eventid = 141 THEN 'Scheduled task deleted'
    WHEN eventid = 200 THEN 'Scheduled task executed'
    END AS detail,
    COUNT(*) AS event_count,
    CAST(JSON_EXTRACT(data,'$.EventData.TaskName') AS TEXT) task_name,
    CASE 
    WHEN eventid = 106 THEN JSON_EXTRACT(data,'$.EventData.UserContext') 
    WHEN eventid IN ('141','140') THEN JSON_EXTRACT(data,'$.EventData.UserName')
    ELSE '-' END AS username,
    JSON_EXTRACT(data,'$.EventData.ActionName') AS action_name,
    JSON_EXTRACT(data,'$.EventData.EnginePID') AS engine_pid,
    JSON_EXTRACT(data,'$.EventData.TaskInstanceId') AS task_instanceID,
    'Task.02.0' AS query
FROM sophos_windows_events
WHERE source = 'Microsoft-Windows-TaskScheduler/Operational'
    AND eventid IN ('106','140','141','200')
    AND time >= $$start_time$$
    AND time <= $$end_time$$
GROUP BY strftime('%Y-%m-%d',datetime), eventid, task_name, username
ORDER BY date_time DESC
