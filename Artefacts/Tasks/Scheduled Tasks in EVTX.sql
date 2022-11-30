SELECT DISTINCT
    strftime('%Y-%m-%dT%H:%M:%SZ',swe.datetime) AS date_time, 
    swe.source,
    CASE WHEN eventid = 106 THEN eventid || ' - Scheduled task created'
    WHEN eventid = 140 THEN eventid || ' - Scheduled task updated'
    WHEN eventid = 141 THEN eventid || ' - Scheduled task deleted'
    WHEN eventid = 200 THEN eventid || ' - Scheduled task executed'
    END AS event_id,
    CAST(JSON_EXTRACT(swe.data,'$.EventData.TaskName') AS TEXT) task_name,
    CASE WHEN eventid = 106 THEN JSON_EXTRACT(swe.data,'$.EventData.UserContext') 
    WHEN eventid IN ('141','140') THEN JSON_EXTRACT(swe.data,'$.EventData.UserName')
    ELSE '-' END AS username,
    JSON_EXTRACT(swe.data,'$.EventData.ActionName') AS action_name,
    JSON_EXTRACT(swe.data,'$.EventData.EnginePID') AS engine_pid,
    JSON_EXTRACT(swe.data,'$.EventData.ResultCode') AS result_code,
    JSON_EXTRACT(swe.data,'$.EventData.TaskInstanceId') AS task_instanceID,
    swe.data as raw,
    'EVTX' AS data_source
FROM sophos_windows_events swe
WHERE swe.source = 'Microsoft-Windows-TaskScheduler/Operational' 
    AND swe.eventid IN ('106','140','141','200')
    AND time >= $$start_time$$
    AND time <= $$end_time$$
GROUP BY task_name, swe.datetime
ORDER BY swe.datetime DESC