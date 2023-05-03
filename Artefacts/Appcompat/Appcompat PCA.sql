/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Program Compatibility Assistant (PCA) is a new Windows artifact introduced in  |
| Windows 11 22H2 that can be used as evidence of program execution.             |
|                                                                                |
| The query gets information from the PcaAppLaunchDic.txt located in             |
| %SystemRoot%\appcompat\pca folder. The file saves the full path of a GUI-based |
| program and the last execution timestamp (UTC)                                 |
|                                                                                |
| VARIABLE                                                                       |
| - path (TYPE: string)                                                          |
|                                                                                |
| REFERENCE                                                                      |
| https://aboutdfir.com/new-windows-11-pro-22h2-evidence-of-execution-artifact/  |
|                                                                                |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/


SELECT
f.path,
strftime('%Y-%m-%dT%H:%M:%SZ', datetime(f.mtime,'unixepoch')) AS last_modified_time,
SUBSTR(grep.line, 1, INSTR(grep.line, '|') - 1) AS program_fullpath,
strftime('%Y-%m-%dT%H:%M:%SZ',SUBSTR(grep.line, INSTR(grep.line, '|') + 1)) AS program_last_execution,
hash.sha256 AS program_sha256,
authenticode.subject_name AS certificate_subject_name,
'AppCompat PCA' AS query 
FROM file f
LEFT JOIN grep USING (path)
LEFT JOIN hash ON program_fullpath = hash.path
LEFT JOIN authenticode ON program_fullpath = authenticode.path
WHERE f.directory LIKE 'C:\Windows\appcompat\pca\' 
AND f.filename = 'PcaAppLaunchDic.txt'
AND program_fullpath LIKE '$$path$$'