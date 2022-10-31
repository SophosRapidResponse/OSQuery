/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Gets AV detections events in Windows Event logs.                               |
| Collects events from Sophos, Windows Defender, Symantec, and                   |
| Carbon Black in Application, Windows Defender/Operational Logs                 |
|                                                                                |          
| Version: 1.1                                                                   |
| Author: Sophos Rapid Response Team                                             |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
	strftime('%Y-%m-%dT%H:%M:%SZ',datetime) AS date_time,
	source,
	provider_name,
	eventid,
	CASE
	WHEN eventid='1006' THEN 'Malware or other potentially unwanted software found'
	WHEN eventid='1007' THEN 'Action performed to protect your system from malware or other potentially unwanted software'
	WHEN eventid='1008' THEN 'Failed attempt to perform an action to protect your system from malware or other potentially unwanted software'
	WHEN eventid='1009' THEN 'Item from quarantine restored'
	WHEN eventid='1010' THEN 'Could not restore item from quarantine'
	WHEN eventid='1011' THEN 'Deleted an item from quarantine'
	WHEN eventid='1012' THEN 'Could not delete an item from quarantine'
	WHEN eventid='1015' THEN 'Suspicious behaviour detected'
	WHEN eventid='1116' THEN 'Malware or potentially unwanted software detected'
	WHEN eventid='1117' THEN 'Action performed to protect your system from malware or other potentially unwanted software'
	WHEN eventid='1118' THEN 'Failed to protect your system from malware or potentially unwanted software'
	WHEN eventid='1119' THEN 'Critical error when trying to take action on malware or other potentially unwanted software'
	WHEN eventid='1120' THEN 'Antivirus has deduced the hashes for a threat resource'
	WHEN eventid='1127' THEN 'Controlled Folder Access(CFA) blocked an untrusted process from making changes to the memory'
	WHEN eventid='33' THEN 'Threat detected by Carbon Black'
	WHEN eventid='5' THEN 'Symantec Antivirus scan detected a virus.'
	WHEN eventid='47' THEN 'Symantec Antivirus took action against a detected threat.'
	WHEN eventid='51' THEN 'Symantec Antivirus finished handling a threat.'
	ELSE 'Other' END as description,
	data AS raw
	'EVTX' AS Data_Source,
	'AV Detections' AS Query
FROM sophos_windows_events 
WHERE source = 'Microsoft-Windows-Windows Defender/Operational' AND eventid in ('1006', '1007', '1008', '1009', '1010', '1011','1012', '1116' , '1117' , '1118', '1119', '1120', '1127')
	OR source = 'Application' AND provider_name = 'Sophos System Protection' AND eventid = '42'
	OR source = 'Application' AND provider_name = 'HitmanPro.Alert' AND eventid = '911'
	OR source = 'Application' AND provider_name LIKE '%Symantec%' AND eventid in ('5','47','51')
	OR source = 'Application' AND provider_name LIKE '%CbDefense%' AND eventid in ('17','33','49')
