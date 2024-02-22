/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Identify shells being spawned from ScreenConnect process.                      |
|                                                                                |
| IMPORTANT                                                                      |
| If the description field results shows 'Cloud' then the process command lines  |
| being spawned are from a cloud managed ScreenConnect instance that would have  |
| been patched already by ConnectWise.                                           |
|                                                                                |
| If the description field results shows 'Self-Hosted' then the command lines    |
| being spawned are from a self-hosted version of ScreenConnect that is          |
| potentially vulnerable and may have been exploited.                            |
|                                                                                |
| The parent_cmdline field contains the version number. If this is under 23.9.8  |
| then it is vulnerable version of ScreenConnect.                                |
|                                                                                |
| Author: MDR Team                                                               |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/



WITH main_query AS (
 SELECT
 date_format(from_unixtime(time), '%Y-%m-%d %H:%i:%S') as date_time,
 time AS epoch_time,
 meta_hostname AS hostname,
 username,
 parent_name,
 parent_cmdline,
 SUBSTRING( parent_cmdline FROM POSITION('&h=' IN parent_cmdline) FOR POSITION('&p=' IN parent_cmdline) - POSITION('&h=' IN parent_cmdline) ) AS instance_url,
 CASE 
 WHEN SUBSTRING( cmdline FROM POSITION('&h=' IN cmdline) FOR POSITION('&p=' IN cmdline) - POSITION('&h=' IN cmdline) ) LIKE '%hostedrmm.com%' THEN 'Cloud'
 WHEN SUBSTRING( cmdline FROM POSITION('&h=' IN cmdline) FOR POSITION('&p=' IN cmdline) - POSITION('&h=' IN cmdline) ) LIKE '%screenconnect.com%' THEN 'Cloud'
 ELSE 'Self-Hosted'
 END AS description,
 NAME,
 cmdline,
 path,
 query_name,
 sophos_pid,
 parent_sophos_pid
 FROM
 xdr_data
 WHERE
 query_name = 'running_processes_windows_sophos'
 AND lower(parent_name) LIKE '%screenconnect.clientservice.exe%'
 AND lower(name) IN ('cmd.exe','powershell.exe')
),
clean_query AS (
 SELECT
 date_format(from_unixtime(time), '%Y-%m-%d %H:%i:%S') as date_time,
 time AS epoch_time,
 meta_hostname AS hostname,
 username,
 NAME,
 parent_name,
 cmdline,
 path,
 query_name,
 sophos_pid,
 parent_sophos_pid
 FROM
 xdr_data
 WHERE
 query_name = (
 'running_processes_windows_sophos'
 )
)
SELECT
 main_query.date_time,
 main_query.epoch_time,
 main_query.hostname Hostname,
 main_query.username username,
 main_query.parent_cmdline AS grandparent_process_cmdline,
 main_query.instance_url AS instance_url,
 main_query.description AS description,
 '►' || main_query.parent_name AS grandparent_process_name,
 '►►' || clean_query.parent_name AS parent_name,
 '►►►' || clean_query.NAME AS process_name,
 main_query.cmdline AS parent_cmdline,
 clean_query.cmdline AS cmdline,
 clean_query.sophos_pid AS process_id,
 'datalake' AS source_data
FROM
 clean_query
 JOIN main_query ON clean_query.parent_sophos_pid = main_query.sophos_pid