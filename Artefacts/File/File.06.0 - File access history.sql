/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Uses file and Process Journals to see file access history.                     |
|                                                                                |
| VARIABLES                                                                      |
| path(filepath) = path of the file you are interested in                        |
| begin(date) = datetime of when to start hunting                                |
| end(date) = datetime of when to stop hunting                                   |
|                                                                                |
| Version: 1.1                                                                   |
| Author: Sophos / @AltShiftPrtScn                                               |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT    
    strftime('%Y-%m-%dT%H:%M:%SZ', datetime(sfj.time,'unixepoch')) date_time,
    spj.process_name,
    CASE sfj.event_type
        WHEN 0 THEN 'Created'
        WHEN 1 THEN 'Renamed'
        WHEN 2 THEN 'Deleted'
        WHEN 3 THEN 'Modified'
        WHEN 4 THEN 'HardLink Created'
        WHEN 5 THEN 'Timestamps Modified'
        WHEN 6 THEN 'Permissions Modified'
        WHEN 7 THEN 'Ownership Modified'
        WHEN 8 THEN 'Accessed'
        WHEN 9 THEN 'Binary File Mapped'
    END event_type,
    replace(sfj.path, rtrim(sfj.path, replace(sfj.path, '\', '')), '') file_name,
    spj.path process_path,
    sfj.path file_path,
    sfj.sophos_pid,
    spj.sha256,
    spp.ml_score,
    spp.pua_score,
    spp.local_rep,
    spp.global_rep,
	'File Journal/Process Journal/Process_Properties' AS data_source,
	'File.06.0' AS query
FROM sophos_file_journal sfj
LEFT JOIN sophos_process_journal spj 
    ON spj.sophos_pid = sfj.sophos_pid
LEFT JOIN sophos_process_properties spp 
    ON spp.sophos_pid = spj.sophos_pid
WHERE sfj.path LIKE '$$path$$'
AND sfj.time > $$begin$$
AND sfj.time < $$end$$
ORDER BY sfj.time DESC