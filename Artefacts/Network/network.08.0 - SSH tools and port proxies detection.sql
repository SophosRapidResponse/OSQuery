/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Gets registry keys associated with usage of Plink/PuTTY, Kitty, WinSCP, and    |
| PortProxy.                                                                     |
|                                                                                |
| IMPORTANT                                                                      |
| Query can bring false positives (legitimate SSH), but can also disclose        |
| unexpected tunneling activity.                                                 |
|                                                                                |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
CASE
	WHEN key LIKE '%\SimonTatham\%' THEN 'PuTTY'
	WHEN key LIKE '%\Martin Prikryl\%' THEN 'WinSCP'
	WHEN key LIKE '%\9bis.com\%' THEN 'KiTTY'
	ELSE 'PortProxy' 
END AS product,
name As address_1, 
CASE 
	WHEN KEY LIKE '%PortProxy%' THEN data
	ELSE NULL 
END AS address_2,
path,
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(mtime,'unixepoch')) AS Last_modified_time,
u.username,
regex_match(path,'(S-[0-9]+(-[0-9]+)+)', '') AS sid,
CASE 
	WHEN KEY LIKE '%PortProxy%' THEN 'Proxy Tunneling'
	ELSE 'SSH Protocol Tunneling' 
END AS data_source,
'network.08.0' AS query
FROM registry
LEFT JOIN users u ON sid = u.uuid
WHERE (key LIKE 'HKEY_USERS\%\SOFTWARE\Martin Prikryl\WinSCP 2\SshHostKeys'
	OR key = 'HKEY_CURRENT_USER\SOFTWARE\Martin Prikryl\WinSCP 2\SshHostKeys'
	OR key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Martin Prikryl\WinSCP 2\SshHostKeys'
	OR key LIKE 'HKEY_USERS\%\SOFTWARE\SimonTatham\PuTTY\%'
	OR key LIKE 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\%'
	OR key LIKE 'HKEY_USERS\%\SOFTWARE\9bis.com\KiTTY\SshHostKeys')
	AND address_1 <> 'Recent sessions'