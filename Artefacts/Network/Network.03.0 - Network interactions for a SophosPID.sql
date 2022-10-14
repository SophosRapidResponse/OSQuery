/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Check the network interactions of a specific process from a SophosPID.         |
|                                                                                |
| VARIABLES                                                                      |
| begin(date) = datetime of when to start hunting                                |
| end(date) = datetime of when to stop hunting                                   |
| SophosPID(SophosPID) = SophosPID of the process                                |
|                                                                                |
| Version: 1.1                                                                   |
| Author: Sophos / @AltShiftPrtScn                                               |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
    strftime('%Y-%m-%dT%H:%M:%SZ', datetime(time,'unixepoch')) AS Datetime,
    sophos_pid,
    strftime('%Y-%m-%dT%H:%M:%SZ', datetime(process_start_time,'unixepoch')) Process_Start_Time,
    source AS Source,
    source_port AS Source_Port,
    destination AS Destination,
    destination_port AS Destination_Port,
    CASE
        protocol
        WHEN 0 THEN 'Unsupported'
        WHEN 1 THEN 'ICMP/ICMPv4'
        WHEN 6 THEN 'TCP'
        WHEN 17 THEN 'UDP'
        WHEN 58 THEN 'ICMPv6'
        ELSE protocol
    END protocol,
	'Process Journal/File/Users' AS Data_Source,
    'Process.06.0' AS Query
FROM
    sophos_ip_journal
WHERE
    sophos_pid = '$$sophosPID$$'
    AND time >= $$begin$$
    AND time <= $$end$$