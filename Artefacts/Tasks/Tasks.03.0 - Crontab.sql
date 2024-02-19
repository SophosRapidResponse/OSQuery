/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Get values from system and user job scheduling with cron                       |
|                                                                                |
| Platforms: MacOS/Linux                                                         |
|                                                                                |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
    command,
    path, 
    minute,
    hour, 
    day_of_month,
    month,
    day_of_week,
    'crontab' AS Query
FROM crontab
