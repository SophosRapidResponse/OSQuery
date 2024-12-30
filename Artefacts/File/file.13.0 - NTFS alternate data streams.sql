/***************************** Sophos.com/RapidResponse *****************************\
| DESCRIPTION                                                                        |
| Identifies the creation of Alternate Data Streams (ADS) in the filesystem within a |
| time range.                                                                        |
|                                                                                    |
| VARIABLES                                                                          |
| - start_time (DATE)                                                                |
| - end_time (DATE)                                                                  |
|                                                                                    |
| Version: 1.0                                                                       |
| Author: Author: The Rapid Response Team | Elida Leite                              |
| github.com/SophosRapidResponse                                                     |
\************************************************************************************/


WITH ProcessedPaths AS (
SELECT 
   sfj.creation_time,
   sfj.path,
   regex_match(sfj.path, '[^\\]+$', 0) AS filename,
   sfj.sophos_pid,
   sfj.subject,
   sfj.time,
   sfj.event_type,
   spj.process_name,
   spj.cmd_line,
   spj.sid,
   u.username
FROM sophos_file_journal sfj
JOIN sophos_process_journal spj ON spj.sophos_pid = sfj.sophos_pid
LEFT JOIN users u ON u.uuid = spj.sid
WHERE sfj.subject = 'FileBinaryChanges' 
   AND sfj.time BETWEEN $$start_time$$ AND $$end_time$$ 
   AND sfj.event_type IN (0, 1, 3)
   AND filename LIKE '%:%' 
)
SELECT 
strftime('%Y-%m-%dT%H:%M:%SZ', datetime(pp.creation_time, 'unixepoch')) AS file_creation_time,
pp.path,
pp.filename,
pp.process_name,
pp.cmd_line,
pp.sophos_pid,
pp.username,
pp.sid,
'File/Process journals' AS Data_Source,
'NTFS ADS' AS Query
FROM ProcessedPaths pp
GROUP BY pp.sophos_pid; 