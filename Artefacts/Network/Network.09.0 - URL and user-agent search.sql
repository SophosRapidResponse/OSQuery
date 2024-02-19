/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Searches for a specific URL or user agent in Sophos Browser Web Flow journals  |
|                                                                                |
| Returns detailed information about the traffic such as  process name, page     |
| status code, user agent, headers, cookies and referrer page.                   |
|                                                                                |
|  VARIABLES                                                                     |
| - url (string): Allow searches by a specific URL                               |
| - user_agent (string): search for a specific user-agent string                 |
| - start_time                                                                   |
| - end_time                                                                     |
|                                                                                |
| The wildcard (%) can be used in one of the variables above.                    |
|                                                                                |
| EXAMPLE                                                                        |
| url = %twitter.com%  AND user-agent = %                                        |
|                                                                                |
| Version: 1.1                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
STRFTIME('%Y-%m-%dT%H:%M:%SZ', DATETIME(swtj.time, 'unixepoch')) AS date_time,
users.username,
spj.process_name,
spj.cmd_line,
swfj.sophos_pid,
CAST (regex_match(swtj.url,'^(?:https?:\/\/)?(?:[^@\/\n]+@)?(?:www\.)?([^:\/\n]+)',0)AS TEXT) hostname,
CAST (swtj.url AS TEXT) url,
swtj.status_code,
CAST (swtj.user_agent AS TEXT) user_agent,
CAST (regex_match(swtj.request_headers, 'cookie":(.*?),',1) AS Text) cookies,
CAST(
    CASE JSON_VALID(swtj.request_headers)
        WHEN 1 THEN (SELECT GROUP_CONCAT(key || ': ' || value, CHAR(10)) FROM JSON_EACH(swtj.request_headers))
        ELSE swtj.request_headers
    END AS TEXT
) AS request_headers,
CAST(
    CASE JSON_VALID(swtj.response_headers)
         WHEN 1 THEN (SELECT GROUP_CONCAT(key || ': ' || value, CHAR(10)) FROM JSON_EACH(swtj.response_headers))
        ELSE swtj.response_headers
    END AS TEXT
) AS response_headers,
swtj.file_type,
swtj.content_type,
swtj.referrer,
'Browser webtransation' AS Data_Source,
'network.09.0' AS Query
FROM sophos_web_transaction_journal AS swtj
LEFT JOIN sophos_web_flow_journal AS swfj ON (
        swfj.time = (CAST(SPLIT(swtj.flow_id, '-', 0) AS INT) - 11644473600)
        AND swfj.flow_id = swtj.flow_id )
LEFT JOIN users ON users.uuid = swfj.owner
JOIN sophos_process_journal AS spj ON spj.sophos_pid = swfj.sophos_pid
WHERE
    swtj.time >= $$start_time$$
    AND swtj.time <= $$end_time$$
    AND (swtj.url LIKE '$$url$$' OR swtj.referrer LIKE '$$url$$')
    AND swtj.user_agent LIKE '$$user_agent$$'