/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Gets values from system and user job scheduling with cron.                     |
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
    'task.03.0' AS Query
FROM crontab
