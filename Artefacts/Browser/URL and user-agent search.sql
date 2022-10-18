/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Allows searches for a particular URL or user-agent in HTTP and Browser Web Flow|
| journals.The first collect data from all Windows processes that contact an URL |
| and the latter collects information specifically from browser activity         |
|                                                                                |
| The query returns detailed information about the traffic such as: process name,|   
| page status_code, user_agent, headers, cookies and referrer page.              |       
|                                                                                |
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
| Author: The Rapid Response Team |Elida Leite                                   |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
    STRFTIME('%Y-%m-%dT%H:%M:%SZ', DATETIME(swtj.time, 'unixepoch')) AS date_time,
    (SELECT username FROM users WHERE uuid = swfj.owner) AS user,
    (SELECT process_name FROM sophos_process_journal AS spj WHERE spj.sophos_pid = swfj.sophos_pid) AS process_name,
    '-' AS cmd_line,
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
    '-' AS headers,
    '-' AS source,
    '-' AS destination,
    swtj.file_type,
    swtj.content_type,
    swtj.referrer,
    'Browser webtransation' AS Data_Source,
    'URL and UserAgent search' AS Query
FROM
    sophos_web_transaction_journal AS swtj
LEFT JOIN
    sophos_web_flow_journal AS swfj ON (
        swfj.time = (CAST(SPLIT(swtj.flow_id, '-', 0) AS INT) - 11644473600)
        AND swfj.flow_id = swtj.flow_id
    )
WHERE
    swtj.time >= $$start_time$$
    AND swtj.time <= $$end_time$$
    AND (swtj.url LIKE '$$url$$'  OR swtj.referrer LIKE '$$url$$')
    AND swtj.user_agent LIKE '$$user_agent$$'


UNION  

SELECT 
    STRFTIME('%Y-%m-%dT%H:%M:%SZ', DATETIME(http.time, 'unixepoch')) AS date_time,
    '-' AS user,
    (SELECT process_name FROM sophos_process_journal AS spj WHERE spj.sophos_pid = http.sophos_pid) AS process_name,
    (SELECT cmd_line FROM sophos_process_journal AS spj WHERE spj.sophos_pid = http.sophos_pid) AS cmd_line,
    http.sophos_pid,
    regex_match(http.headers,'Host:(.*)', 1) AS hostname,
    http.url,
    '-' AS status_code,
    regex_match(http.headers,'User-Agent:(.*)', 1) AS user_agent,
    regex_match(http.headers,'Cookie:(.*)',1) AS cookies, 
    '-' AS request_headers,
    '-' AS response_headers,
    http.headers,
    CAST (http.source || ':' || http.source_port AS TEXT) source,
    CAST (http.destination || ':' || http.destination_port AS TEXT) destination,
    '-' AS file_type,
    '-' AS content_type,
    '-' AS referrer,
    'http journals' AS Data_Source,
    'URL and UserAgent search' Query
FROM sophos_http_journal http
WHERE http.time >= $$start_time$$
    AND http.time <= $$end_time$$
    AND http.url LIKE '$$url$$' 
    AND user_agent LIKE '$$user_agent$$'


