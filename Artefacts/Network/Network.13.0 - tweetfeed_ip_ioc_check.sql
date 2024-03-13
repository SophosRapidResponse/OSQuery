/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Pulls IP IOC's from Tweetfeed and compares to currently active network traffic |
|                                                                                |
|                                                                                |
|                                                                                |
|                                                                                |
| Query Type: Endpoint                                                           |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team | Lee Kirkpatrick                              |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/


WITH tweetfeed_ioc AS (
  SELECT 
    JSON_EXTRACT(value, '$.value') AS ioc,
    JSON_EXTRACT(value, '$.tweet') AS tweet
  FROM curl, json_each(result)
  WHERE url='https://api.tweetfeed.live/v1/month/@drb_ra/ip' -- this API call can be edited based on details from https://tweetfeed.live/api.html - the API call will need to return only IP values!
)

SELECT
  snj.sophos_pid,
  spj.path,
  spj.cmd_line,
  snj.destination,
  snj.destination_port,
  tweetfeed_ioc.tweet
FROM sophos_network_journal snj
LEFT JOIN sophos_process_journal spj USING (sophos_pid)
JOIN tweetfeed_ioc ON snj.destination = tweetfeed_ioc.ioc
