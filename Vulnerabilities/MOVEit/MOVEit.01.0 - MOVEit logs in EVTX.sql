SELECT
  strftime('%Y-%m-%dT%H:%M:%SZ',datetime) AS date_time,
  eventid,
  data,
  source AS data_source,
  'MOVEit.01.0' AS query
FROM sophos_windows_events
WHERE
  eventid = 0
  AND source = 'MOVEit'