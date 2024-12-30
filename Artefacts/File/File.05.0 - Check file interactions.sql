/*************************** Sophos.com/RapidResponse ***************************\                                                                               |
| DESCRIPTION                                                                    |
| Uses file and Process Journals to see what interactions a file had.            |
|                                                                                |
| VARIABLES                                                                      |
| sha256(sha256) = sha256 of the file you are interested in                      |
| begin(date) = datetime of when to start hunting                                |
| end(date) = datetime of when to stop hunting                                   |
|                                                                                |
| Version: 1.1                                                                   |
| Author: Sophos / @AltShiftPrtScn                                               |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

WITH shaInterractions (time, action, process_name, file_path, sophos_pid, sid) AS (
    /* Check file modifications for the correct sha */
    SELECT
        sfj.time,
        CASE sfj.event_type
            WHEN 1 THEN 'File Renamed'
            WHEN 8 THEN 'File Accessed'
            ELSE 'Unknown Event Type'
        END action,
        spj.process_name process_name,
        sfj.path file_path,
        sfj.sophos_pid sophos_pid,
        spj.sid sid
    FROM sophos_file_journal sfj
    LEFT JOIN sophos_process_journal spj USING (sophos_pid)
    WHERE
        (
            sfj.subject = 'FileOtherChanges'
            OR sfj.subject = 'FileBinaryReads'
            OR sfj.subject = 'FileOtherReads'
            OR sfj.subject = 'FileBinaryChanges'
        )
        AND sfj.sha256 = '$$sha256$$'
        AND sfj.event_type IN (1,8)
        AND sfj.time >= $$begin$$
        AND sfj.time <= $$end$$

    UNION ALL

    /* Check processes for the correct sha */
    SELECT
        spj.time,
        'Process Start' action,
        spj.process_name process_name,
        spj.path filePath,
        spj.sophos_pid sophos_pid,
        spj.sid sid
    FROM sophos_process_journal spj
    WHERE
        event_type = 0
        AND spj.time >= $$begin$$
        AND spj.time <= $$end$$
        AND sha256 = '$$sha256$$'
)

/* Cleanup results and add extra information */
SELECT
    strftime('%Y-%m-%dT%H:%M:%SZ', datetime(si.time,'unixepoch')) dateTime,
    users.username,
    si.process_name,
    CAST((
        SELECT spj.path
        FROM sophos_process_journal spj
        WHERE spj.sophos_pid = si.sophos_pid
    ) AS TEXT) process_path,
    si.action action,
    si.file_path file_path,
    CAST(si.sophos_pid AS TEXT) sophos_pid,
    CASE (SELECT 1 FROM hash h WHERE h.path = si.file_path AND h.sha256 = '$$sha256$$')
        WHEN 1 THEN 'True'
        ELSE 'False'
    END on_disk
FROM shaInterractions si
LEFT JOIN users on users.uuid LIKE si.sid