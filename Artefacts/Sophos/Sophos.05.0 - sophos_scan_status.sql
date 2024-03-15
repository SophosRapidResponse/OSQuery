/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Extracts details regarding Sophos Scans:                                       |
|  - Whether a scan has been started and by what method                          |
|  - How long the scan took                                                      |
|                                                                                |
|                                                                                |
| Query Type: Endpoint                                                           |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team | Lee Kirkpatrick                              |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/


WITH scan_data AS (
    SELECT 
        MAX(regex_match(grep.line, '(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3}Z)', 0)) AS Datetime,
        grep.line AS LogLine,
        CASE
            WHEN grep.pattern = 'SophosScanCoordinator launched by SCHEDULER' THEN 'Scheduled Scan Started'
            WHEN grep.pattern = 'SophosScanCoordinator launched by CENTRAL' THEN 'Central Scan Started'
            WHEN grep.pattern = 'SophosScanCoordinator launched by GUI' THEN 'GUI Scan Started'
            WHEN grep.pattern = 'Finished File scan' THEN 'Finished Scan'
        END AS Description,
        MAX(regex_match(grep.line, '(\d+)\s*seconds\b', 1)) AS 'ScanTime (seconds)',
        ROUND(CAST(MAX(regex_match(grep.line, '(\d+)\s*seconds\b', 1)) AS REAL) / 3600, 2) AS 'ScanTime (hours)'
    FROM file
    CROSS JOIN grep ON (grep.path = file.path)
    WHERE
        file.path LIKE 'C:\ProgramData\Sophos\Endpoint Defense\Logs\SophosScanCoordinator.log'
        AND (
            grep.pattern = 'SophosScanCoordinator launched by SCHEDULER'
            OR grep.pattern = 'SophosScanCoordinator launched by CENTRAL'
            OR grep.pattern = 'SophosScanCoordinator launched by GUI'
            OR grep.pattern = 'Finished File scan'
        )
    GROUP BY Description
)

SELECT
    Datetime,
    LogLine,
    Description,
    `ScanTime (seconds)`,
    `ScanTime (hours)`
FROM scan_data
