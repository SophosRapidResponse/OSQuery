/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Gets a list of applications executed from Windows Prefetch.                    |
|                                                                                |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/


SELECT
    Path, 
    Filename, 
    Hash,
    STRFTIME('%Y-%m-%dT%H:%M:%SZ', DATETIME(last_run_time, 'unixepoch')) AS Last_Run_Time,
    Other_Run_Times,
    (
        SELECT
            GROUP_CONCAT(STRFTIME('%Y-%m-%dT%H:%M:%SZ', DATETIME(value, 'unixepoch')), CHAR(10))
        FROM JSON_EACH('[' || other_run_times || ']')
    ) AS Other_Run_Times_Readable,
    Run_Count,
    Size,
    Volume_Serial,
    Volume_Creation,
    Accessed_Files_Count,
    Accessed_Directories_Count,
    Accessed_Files_Count,
    Accessed_Files,
   (
        WITH RECURSIVE split(word, str) AS (
            SELECT
                '',
                Accessed_Files || ','
            UNION ALL
            SELECT
                SUBSTR(str, 0, INSTR(str, ',')),
                SUBSTR(str, INSTR(str, ',') + 1)
            FROM split
            WHERE str != ''
        )
        SELECT
            GROUP_CONCAT(word, CHAR(10))
        FROM split
        WHERE word != ''
    ) AS Accessed_Files_List,
    Accessed_Directories,
     (
        WITH RECURSIVE split(word, str) AS (
            SELECT
                '',
                Accessed_Directories || ','
            UNION ALL
            SELECT
                SUBSTR(str, 0, INSTR(str, ',')),
                SUBSTR(str, INSTR(str, ',') + 1)
            FROM split
            WHERE str != ''
        )
        SELECT
            GROUP_CONCAT(word, CHAR(10))
        FROM split
        WHERE word != ''
    ) AS Accessed_Directories_List,
    'Prefetch' AS Data_Source,
    'Prefetch.01.0' AS Query
FROM
   prefetch   
ORDER BY Last_Run_Time DESC;
