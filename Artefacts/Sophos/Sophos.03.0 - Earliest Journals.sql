/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| The query checks when the Sophos journals were first created for each journal  |
| type.                                                                          |
|                                                                                |
|                                                                                |
| Version: 2.0                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

WITH subjects AS (
    SELECT
        filename as subject
    FROM file
    WHERE
        directory = 'C:\ProgramData\Sophos\Endpoint Defense\Data\Event Journals\SophosED\'
),
journal_files AS (
    SELECT
        subjects.subject,
        file.directory,
        SUM(size) AS size,
        MIN(CASE SPLIT(filename, '.', 1)
            WHEN 'bin' THEN CAST(SPLIT(filename, '-.', 2) AS INT)
            WHEN 'xz' THEN CAST(SPLIT(filename, '-', 3) AS INT)
        END) AS first_event
    FROM subjects
    LEFT JOIN file ON (file.directory = 'C:\ProgramData\Sophos\Endpoint Defense\Data\Event Journals\SophosED\' || subjects.subject)
    WHERE filename LIKE '%.bin' OR filename LIKE '%.xz'
    GROUP BY subjects.subject
)
SELECT
    CASE
        WHEN subject = 'AmsiScanRequestsJScript' THEN 'Sophos_AmsiScanRequestJScript_Journal'
        WHEN subject = 'AmsiScanRequestsPowerShell' THEN 'Sophos_AmsiScanRequestPowerShell_Journal'
        WHEN subject = 'DirectoryChanges' THEN 'Sophos_DirectoryChanges_Journal'
        WHEN subject = 'Dns' THEN 'Sophos_Dns_Journal'
        WHEN subject = 'FileBinaryChanges' THEN 'Sophos_FileBinaryChanges_Journal'
        WHEN subject = 'FileBinaryReads' THEN 'Sophos_FileBinaryReads_Journal'
        WHEN subject = 'FileDataChanges' THEN 'Sophos_FileDataChanges_Journal'
        WHEN subject = 'FileDataReads' THEN 'Sophos_FileDataReads_Journal'
        WHEN subject = 'FileHashes' THEN 'Sophos_FileHashes_Journal'
        WHEN subject = 'FileOtherChanges' THEN 'Sophos_FileOtherChanges_Journal'
        WHEN subject = 'FileOtherReads' THEN 'Sophos_FileOtherReads_Journal'
        WHEN subject = 'FileProperties' THEN 'Sophos_FileProperties_Journal'
        WHEN subject = 'Http' THEN 'Sophos_Http_Journal'
        WHEN subject = 'Image' THEN 'Sophos_Image_Journal'
        WHEN subject = 'Network' THEN 'Sophos_Network_Journal'
        WHEN subject = 'Process' THEN 'Sophos_Process_Journal'
        WHEN subject = 'Registry' THEN 'Sophos_Registry_Journal'
        WHEN subject = 'RuntimeIOCs' THEN 'Sophos_RuntimeIOCs_Journal'
        WHEN subject = 'System' THEN 'Sophos_System_Journal'
        WHEN subject = 'Thread' THEN 'Sophos_Thread_Journal'
        WHEN subject = 'Url' THEN 'Sophos_Url_Journal'
        WHEN subject = 'WinSec' THEN 'Sophos_WinSec_Journal'
        WHEN subject = 'Ip' THEN 'Sophos_Ip_Journal'
        ELSE subject
        END As journal,
    directory,
    strftime('%Y-%m-%dT%H:%M:%SZ', datetime((first_event / 10000000 - 11644473600),'unixepoch')) As earliest_journal_entry,
    PRINTF('%.2f', CAST(size AS FLOAT) / 1024 / 1024) AS size_mb,
    PRINTF('%.2f', CAST((
        STRFTIME('%s', 'now') - (first_event / 10000000 - 11644473600)
    ) AS FLOAT) / (60 * 60 * 24)) AS days_of_data,
    'File' AS Data_Source,
    'Sophos.03.0' AS Query
FROM journal_files;