/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Extracts connection details from the remote desktop application                |
|                                                                                |
| Reference: https://tinyurl.com/mtxdjw4j                                        |
|                                                                                |
| Query Type: Endpoint                                                           |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team | Lee Kirkpatrick                              |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/


SELECT
    grep.filepath,
    REPLACE(grep.path, regex_match(grep.path, '(.+\\)', 0), '') AS Filename,
    regex_match(grep.filepath, 'Users\\(.*?)\\', 1) AS Username,
    regex_match(grep.line, 'ConnectionId>(.*?)<', 1) AS ConnectionId,
    regex_match(grep.line, 'Description>(.*?)<', 1) AS Description,
    regex_match(grep.line, 'LastLaunch>(.*?)<', 1) AS LastLaunch,
    regex_match(grep.line, 'DisplayName>(.*?)<', 1) AS DisplayName,
    regex_match(grep.line, 'FriendlyName>(.*?)<', 1) AS FriendlyName,
    regex_match(grep.line, 'HostName>(.*?)<', 1) AS HostName
FROM
    file
JOIN
    grep ON (grep.path = file.path)
WHERE
    (file.path LIKE 'C:\Users\%\AppData\Local\Packages\Microsoft.RemoteDesktop_8wekyb3d8bbwe\LocalState\RemoteDesktopData\LocalWorkspace\connections\%.model'
    OR file.path LIKE 'C:\Users\%\AppData\Local\Packages\Microsoft.RemoteDesktop_8wekyb3d8bbwe\LocalState\RemoteDesktopData\JumpListConnectionArgs\%.model')
    AND grep.pattern IN ('a:Description', 'a:LastLaunch', 'a:DisplayName', 'a:ConnectionId', 'a:FriendlyName', 'a:HostName');
