/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| The query get registry keys associated with Plink/PuTTY sessions, PortProxy    |
| configuration created with netsh, and WinSCP usage.                            |
|                                                                                |
|                                                                                |
| IMPORTANT                                                                      |
| Query can bring false positives (legitimate SSH), but can also disclose        |
| unexpected tunneling activity.                                                 |
|                                                                                |
| Author: The Rapid Response Team | Elida Leite                                  |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT 
	path As Path,
	name As Tunnel_or_Port, 
	CASE 
	WHEN KEY LIKE '%PortProxy%' THEN data
	ELSE '-' 
	END AS Connect_Address,
	strftime('%Y-%m-%dT%H:%M:%SZ',datetime(mtime,'unixepoch')) AS Last_modified_time,
	'High' As Potential_FP_chance,
	'Registry' AS Data_Source,
	CASE 
	WHEN KEY LIKE '%PortProxy%' THEN 'T1090 - Proxy Tunneling'
	ELSE 'T1572 - SSH Protocol Tunneling' 
	END AS Query
FROM registry
WHERE (key = 'HKEY_USERS\%\SOFTWARE\Martin Prikryl\WinSCP 2\SshHostKeys'
	OR key = 'HKEY_CURRENT_USER\SOFTWARE\Martin Prikryl\WinSCP 2\SshHostKeys'
	OR key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Martin Prikryl\WinSCP 2\SshHostKeys'
	OR key LIKE 'HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\%'
	OR key LIKE 'HKEY_USERS\%\SOFTWARE\SimonTatham\PuTTY\%'
	OR key LIKE 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\%')
ORDER BY Last_modified_time;