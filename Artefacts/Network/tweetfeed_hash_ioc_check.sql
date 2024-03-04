/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Pulls SHA256 IOC's from Tweetfeed and compares to currently active             |
| network traffic                                                                |
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
  WHERE url='https://api.tweetfeed.live/v1/month/sha256' -- this API call can be edited based on details from https://tweetfeed.live/api.html - the API call will need to return only SHA256 values!
)

SELECT
    f.path AS Path,
    f.directory AS Directory,
    f.filename AS Filename,
    f.size AS Size,
    strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.btime,'unixepoch')) AS 'First_Created_On_Disk(btime)', 
    strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.ctime,'unixepoch')) AS 'Last_Status_Change(ctime)', 
    strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.mtime,'unixepoch')) AS 'Last_Modified(mtime)', 
    strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.atime,'unixepoch')) AS 'Last_Accessed(atime)',
    h.sha256 AS SHA256,
    tweetfeed_ioc.tweet,
    f.attributes AS Attributes
FROM file f 
JOIN hash h ON f.path = h.path
JOIN tweetfeed_ioc ON h.SHA256 = tweetfeed_ioc.ioc
WHERE
    f.Path LIKE '$$directory$$'
