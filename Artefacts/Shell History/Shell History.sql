/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Line-delimited table of per-user bash history                                  |
|                                                                                |
| VARIABLE                                                                       |
|   - IOC: you can search for shell history associated with an username OR a     |
|          a particular string in the commandline                                |
|                                                                                |
| TIP                                                                            |
| To get everything, please include the wildcard "%"                             |
|                                                                                |
| Version: 1.0                                                                   |
| Author: Sophos and The Rapid Response Team                                     |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
    users.username,
    shell_history.uid,
    CASE
        WHEN shell_history.time = 0 THEN 'unknown'
        ELSE STRFTIME('%Y-%m-%dT%H:%M:%SZ', DATETIME(shell_history.time, 'unixepoch'))
    END AS date_time,
    shell_history.command,
    shell_history.history_file,
    'Shell_history/User' AS Data_Source,
    'Shell-history.01.0' AS Query
FROM shell_history
INNER JOIN users
    USING (uid)
WHERE users.username LIKE '%$$IOC$$%' OR shell_history.command LIKE '%$$IOC$$%'