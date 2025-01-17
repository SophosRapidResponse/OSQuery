/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| The query gets URL activity from the Sophos URL, HTTP, and DNS journals. Enter |
| the URL as a variable. Otherwise, the query won't generate results due to the  |
| large amount of data collected by these journals. The query also uses the      |
| Sophos Process Journal to provide additional context about the event.          |
|                                                                                |
| TIP                                                                            |
| This query can be used to get information about files downloaded/executed by   |
| searching for file extensions (.exe, .zip, .rar, .js, .ps1)                    |
|                                                                                |
| VARIABLES                                                                      |
| - $$start_time$$ (date) = datetime of when to start hunting                    |
| - $$end_time$$ (date) = datetime of when to start hunting                      |
| - $$url$$ (string) = IP, URL, domain, file extension (.exe, .js, .ps1)         |
|                                                                                |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/


with url_events (time, sophos_pid, url,journal_subject) AS (
    SELECT 
        time,
        sophos_pid,
        url,
        'url' AS journal_subject
    FROM sophos_url_journal
    WHERE
        time >= $$start_time$$
        AND time <= $$end_time$$
        AND url LIKE '%$$url$$%'

    UNION ALL

    SELECT 
        time,
        sophos_pid,
        url,
        'http' AS journal_subject
    FROM sophos_http_journal
    WHERE
        time >= $$start_time$$
        AND time <= $$end_time$$
        AND url LIKE '%$$url$$%'

     UNION ALL

    SELECT
        time,
        sophos_pid,
        name,
        'dns' AS journal_subject
    FROM sophos_dns_journal
    WHERE
        time >= $$start_time$$
        AND time <= $$end_time$$
        AND name like '%$$url$$%'
)

SELECT
    STRFTIME('%Y-%m-%dT%H:%M:%SZ', MIN(DATETIME(url_events.time, 'unixepoch'))) AS first_date_time,
    STRFTIME('%Y-%m-%dT%H:%M:%SZ', MAX(DATETIME(url_events.time, 'unixepoch'))) AS last_date_time,
    COUNT(*) AS instances,
    (SELECT username FROM users WHERE uuid LIKE sid) AS username,
    process_journal.process_name AS process_name,
    process_journal.path As path,
    process_journal.cmd_line AS cmd_line,
    url_events.url,
    url_events.sophos_pid AS sophos_pid,
    process_journal.parent_sophos_pid As sophos_parent_pid,
    CAST ( (Select spj2.path from sophos_process_journal spj2 where spj2.sophos_pid = process_journal.parent_sophos_pid) AS text) parent_path, 
    CAST ( (Select spj2.process_name from sophos_process_journal spj2 where spj2.sophos_pid = process_journal.parent_sophos_pid) AS text) parent_process,
    CAST ( (Select spj2.cmd_line from sophos_process_journal spj2 where spj2.sophos_pid = process_journal.parent_sophos_pid) AS text) parent_cmd_line,
    url_events.journal_subject AS journal_subject,
    'Sophos URL/HTTP/DNS/Process journals' AS Data_Source,
    'Network.05.0 - URL activity' AS Query
FROM url_events AS url_events
LEFT JOIN sophos_process_journal AS process_journal
    ON url_events.sophos_pid = process_journal.sophos_pid
GROUP BY
    url_events.sophos_pid,
    url_events.url,
    url_events.journal_subject