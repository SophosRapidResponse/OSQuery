/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Check for temporary user creation XML files on disk within a time range.       |
| This file can be an indicator for possible exploitation of CVE-2024-1709.      |
|                                                                                |
| VARIABLES                                                                      |
| - begin_time                                                                   |
| - end_time                                                                     |
|                                                                                |
| CVE-2024-1708 and CVE-2024-1709                                                |
| https://www.huntress.com/blog/a-catastrophe-for-control-understanding-the-     |
| screenconnect-authentication-bypass                                            |
|                                                                                |
| Query Type: Endpoint                                                           |
| Author: The Rapid Response Team | Lee Kirkpatrick                              |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(sfj.time,'unixepoch')) AS 'date_time',
sfj.subject,
sophos_process_journal.cmd_line,
sfj.path,
sfj.file as 'filename',
'process/file journals' AS data_source,
'ScreenConnect.06.' AS query
FROM sophos_file_journal AS sfj
JOIN sophos_process_journal USING (sophos_pid)
WHERE
sfj.path LIKE 'C:\Windows\Temp\ScreenConnect\%\%.xml'
AND sfj.event_type = 0
AND sfj.time > $$begin_time$$
AND sfj.time < $$end_time$$