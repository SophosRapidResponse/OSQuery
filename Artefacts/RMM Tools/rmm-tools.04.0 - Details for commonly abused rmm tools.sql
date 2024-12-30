/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Extracts details from the commonly abused RMM tools.                           |
|                                                                                |
| Query Type: Endpoint                                                           |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team | Lee Kirkpatrick                              |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/


SELECT 
	grep.path,
	grep.line as Data,
	regex_match(grep.line, "(\d+\.\d+\.\d+\.\d+)", 0) AS IP_Address,
	CASE
		--AnyDesk
		WHEN grep.pattern = 'Logged in from' THEN 'AnyDesk Login'
		WHEN grep.pattern = 'Preparing files' THEN 'AnyDesk File Transfer'

		--Splashtop
		WHEN grep.pattern = 'public IP' THEN 'Splashtop Login'
		WHEN grep.pattern = 'uploadFile' THEN 'Splashtop File Upload'
		WHEN grep.pattern = 'File::' THEN 'Splashtop File Download'
		WHEN grep.pattern = 'Upload Completed' THEN 'Splashtop File Upload'

		--Atera
		WHEN grep.pattern = ' Command: ' THEN 'Atera Command'

		--TeamViewer
		WHEN grep.pattern = 'Send file' THEN 'TeamViewer Upload file'
		WHEN grep.pattern = 'Write file' THEN 'TeamViewer Download file'
		WHEN grep.pattern = 'UDPv4: punch received' THEN 'TeamViewer Login'
	END AS 'RMM_Tool'
FROM file
CROSS JOIN grep ON (grep.path = file.path)
WHERE
(
	--AnyDesk
	file.path LIKE 'C:\ProgramData\AnyDesk\ad_svc.trace'
	OR file.path LIKE 'C:\Users\%\AppData\Roaming\AnyDesk\ad.trace'

	--Splashtop
	OR file.path LIKE 'C:\Program Files (x86)\Splashtop\Splashtop Remote\Server\log\SPLog%'
	OR file.path LIKE 'C:\ProgramData\Splashtop\Temp\log\FTCLog%'

	--Atera
	OR file.path LIKE 'C:\Program Files\ATERA Networks\AteraAgent\Packages\AgentPackageRunCommandInteractive\log%'

	--TeamViewer
	OR file.path LIKE 'C:\Program Files\TeamViewer\TeamViewer%_Logfile%'
)
AND
(
	--AnyDesk
	grep.pattern = 'Logged in from'
	OR grep.pattern = 'Preparing files'

	--Splashtop
	OR grep.pattern = 'public IP'
	OR grep.pattern = 'uploadFile'
	OR grep.pattern = 'File::'
	OR grep.pattern = 'Upload Completed'

	--Atera
	OR grep.pattern = ' Command: '

	--TeamViewer
	OR grep.pattern = 'Send file'
	OR grep.pattern = 'Write file'
	OR grep.pattern = 'UDPv4: punch received'
)


--Atera Registry Info
UNION ALL

SELECT 
path,
data,
'' AS IP_Address,
'Atera User' AS RMM_Tool
FROM registry
WHERE
key LIKE 'HKEY_LOCAL_MACHINE\SOFTWARE\ATERA Networks\AlphaAgent'
AND name = 'IntegratorLogin'

--Splashtop Registry Info
UNION ALL

SELECT 
path,
data,
'' AS IP_Address,
CASE
WHEN name = 'Client_DisplayName' THEN 'Splashtop User'
WHEN name = 'DeviceName' THEN 'Splashtop Last Connected Hostname'
END AS RMM_Tool
FROM registry
WHERE
(
key LIKE 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Splashtop Inc.\%%'
OR key LIKE 'HKEY_LOCAL_MACHINE\SOFTWARE\Splashtop Inc.\%%'
OR key LIKE 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Splashtop Inc.\Splashtop Remote Server\%%'
OR key LIKE 'HKEY_LOCAL_MACHINE\SOFTWARE\Splashtop Inc.\Splashtop Remote Server\%%')
AND name IN('Client_DisplayName','DeviceName','Client_IP')

--TeamViewer Registry Info
UNION ALL

SELECT
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(mtime,'unixepoch')) as ModifiedTime, 
data,
'' AS IP_Address,
CASE
WHEN name = 'Meeting_UserName' THEN 'TeamViewer Username'
WHEN name = 'CurrentSelectedLanguage' THEN 'TeamViewer Language'
END AS RMM_Tool
FROM registry
WHERE
(
key like 'HKEY_USERS\%\SOFTWARE\TeamViewer'
OR key like 'HKEY_CURRENT_USER\SOFTWARE\TeamViewer'
)
AND name IN('Meeting_UserName','CurrentSelectedLanguage')