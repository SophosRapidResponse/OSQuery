/*************************** Sophos.com/RapidResponse ********************************\
| DESCRIPTION                                                                         |
| The query checks for evidence of Rclone, Ngrok and Tor in the filesystem using Yara.|
| The path for the directories in which the scan will occur is hardcoded in the query |
|                                                                                     |
| Author: The Rapid Response Team | Elida Leite                                       |
| github.com/SophosRapidResponse                                                      |
\**************************************************************************************/


WITH Signature_Rules(Yara_Sig_Rule) AS
(
	SELECT
	CAST(result AS TEXT) Yara_Sig_Rule
	FROM curl
	WHERE
	url = 'https://gist.githubusercontent.com/Elida001/2689d0a6787f9cf91028f9157a843c77/raw/906513d34a3eedd33834cc30b77f4f1039dd6726/Exfiltration.yara'
)

SELECT
	y.matches,
	y.path,
	datetime(file.btime, 'unixepoch') As Creation_time,
	datetime(file.mtime, 'unixepoch') As Modification_time,
	h.SHA256,
	'Yara/File/Hash' As Data_Source,
	'T1567.002 - Rclone and other tools' As Query
FROM yara y
JOIN hash h ON y.path = h.path
JOIN file ON y.path = file.path
WHERE sigrule IN (SELECT Yara_Sig_Rule FROM Signature_Rules) 
	AND (y.path LIKE 'C:\%' OR y.path LIKE 'C:\%\%' OR y.path LIKE 'C:\Users\%\%')
	AND count > 0