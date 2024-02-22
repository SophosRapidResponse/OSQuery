/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Look for the trailing slash after SetupWizard.aspx in the IIS logs, which can  |
| be an indicator of possible exploitation of Screenconnect auth bypass.         |
|                                                                                |
| The query will bring results when finding the string: SetupWizard.aspx in IIS  |
| logs for February 2024. To allow the query to be adaptable for other months,   |
| you can change the value for filename: u_ex_YYMM%.log.                         |
|                                                                                |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/


SELECT 
    grep.path,
    grep.line,
    file.directory,
    file.filename,
    strftime('%Y-%m-%dT%H:%M:%SZ',datetime(file.mtime,'unixepoch')) AS 'last_modified_time', 
    strftime('%Y-%m-%dT%H:%M:%SZ',datetime(file.btime,'unixepoch')) AS 'created_time',
    'grep/file' AS data_source,
    'ScreenConnect.01.' AS Query
FROM 
    file
CROSS JOIN 
    grep ON (grep.path = file.path)
WHERE
    file.directory LIKE 'C:\inetpub\logs\LogFiles\W3SVC%'
    AND grep.pattern = 'SetupWizard.aspx/'
    AND file.filename LIKE 'u_ex2402%.log'
