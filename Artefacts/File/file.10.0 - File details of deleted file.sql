/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| This query returns details such as the file's creation date, SHA-256 hash, and |
| other relevant information for files deleted while Sophos was installed. The   |
| 'deleted_time' value must be within approximately 2 hours of the file's        |
| deletion. Note that the file may have been created before Sophos was installed.|
|                                                                                |
| VARIABLES                                                                      |
| deleted_time(date) = datetime of approximately when the file was deleted       |
| path(filepath) = file path to hunt for                                         |
|                                                                                |
| Version: 1.0                                                                   |
| Author: @AltShiftPrtScn                                                        |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/


WITH sfj_converted AS (
  SELECT 
    sfj.*,
    strftime('%Y-%m-%dT%H:%M:%SZ', datetime(time, 'unixepoch')) AS deleted_time,
    strftime('%Y-%m-%dT%H:%M:%SZ', datetime(sfj.creation_time, 'unixepoch')) AS first_created_on_disk,
    strftime('%Y-%m-%dT%H:%M:%SZ', datetime(sfj.change_time, 'unixepoch')) AS last_changed,
    strftime('%Y-%m-%dT%H:%M:%SZ', datetime(sfj.last_write_time, 'unixepoch')) AS last_modified,
    strftime('%Y-%m-%dT%H:%M:%SZ', datetime(sfj.last_access_time, 'unixepoch')) AS last_accessed
  FROM sophos_file_journal sfj
)

SELECT 
  deleted_time,
  first_created_on_disk,
  last_changed,
  last_modified,
  last_accessed,
  sfj_converted.path,
  sfj_converted.sha256,
  sfj_converted.file_size,
  'File Journal' AS data_source,
  'File.10' AS query
FROM sfj_converted
WHERE sfj_converted.event_type = 2
  AND (sfj_converted.time BETWEEN CAST($$deleted_time$$ AS INT) - 3600 AND CAST($$deleted_time$$ AS INT) + 3600)
  AND sfj_converted.path LIKE '$$path$$'


