/*************************** Sophos.com/RapidResponse *****************************\
| DESCRIPTION                                                                      |
| When a PsExec command is executed, a .key file is written to the "C:\Windows"    |
| folder on the target system, which contains the information from the source      |
| hostname that executed the PsExec command. It a great artefact to identify       |
| the source of the lateral movement activity.                                     |
|                                                                                  |
| The key file has the following naming convention:                                |
| C:\Windows\PSEXEC-[Source Hostname]-[8 Unique Characters].key                    |
|                                                                                  |
| The character values correspond to the hash of the command executed from the     |
| source machine.                                                                  |
|                                                                                  |
| This query uses Sophos journals, therefore, it should be provided with a time    |
| range as a variable.                                                             |
|                                                                                  |
| VARIABLES                                                                        |
| - start_time (type: DATE)                                                        |
| - end_time   (type: DATE)                                                        |
|                                                                                  |
| The .key file is generated on the PsExec v2.30 and above.                        |
| It could be identifed in the Prefetch and USN Journal file.                      |
|                                                                                  |
| Query Type: Endpoint                                                             |
| Author: The Rapid Response Team | Elida Leite                                    |
| github.com/SophosRapidResponse                                                   |
\**********************************************************************************/

SELECT
STRFTIME('%Y-%m-%dT%H:%M:%SZ', DATETIME(time, 'unixepoch')) AS date_time,
sophos_pid,
subject,
action,
object
FROM sophos_process_activity
WHERE
subject = 'FileOtherReads'
AND action = 'accessed'
AND object LIKE 'C:\Windows\PSEXEC-%'
AND time >= $$start_time$$
AND time <= $$end_time$$
