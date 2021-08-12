/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| This collects various event IDs from the Security event log that relate to     |
| user and group changes, including account creation, password resets, adding to |
| groups and account deletion.                                                   |
|                                                                                |
| VARIABLES                                                                      |
| days(string) = how many days back from NOW to search                           |
|                                                                                |
| Version: 1.0                                                                   |
| Author: @AltShiftPrtScn / Elida Leite                                          |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
   source AS Source,
   eventid AS Event_ID,
   CAST(datetime(time, 'unixepoch') AS TEXT) AS Datetime,
   CASE
    WHEN eventid IN('4730', '4734', '4758') then CHAR(39) || JSON_EXTRACT(data, '$.EventData.SubjectUserName') || CHAR(39) || ' deleted the security group ' || CHAR(39) || JSON_EXTRACT(data, '$.EventData.TargetUserName') || CHAR(39)
    when eventid = 4740 then 'Account Locked'
	WHEN eventid IN('4726') then CHAR(39) || JSON_EXTRACT(data, '$.EventData.SubjectUserName') || CHAR(39) || ' deleted the user ' || CHAR(39) || JSON_EXTRACT(data, '$.EventData.TargetUserName') || CHAR(39)
    when eventid = 4740 then 'Account Locked'
    WHEN eventid IN ('4727', '4754', '4731') then CHAR(39) || JSON_EXTRACT(data, '$.EventData.SubjectUserName') || CHAR(39) || ' created the new security group ' || CHAR(39) || JSON_EXTRACT(data, '$.EventData.TargetUserName') || CHAR(39)
    WHEN eventid = 4720 then CHAR(39) || JSON_EXTRACT(data, '$.EventData.SubjectUserName') || CHAR(39) || ' created the new user ' || CHAR(39) || JSON_EXTRACT(data, '$.EventData.TargetUserName') || CHAR(39)
    WHEN eventid = 4767 then CHAR(39) || JSON_EXTRACT(data, '$.EventData.SubjectUserName') || CHAR(39) || ' unlocked the user account ' || CHAR(39) || JSON_EXTRACT(data, '$.EventData.TargetUserName') || CHAR(39)
    WHEN eventid = 4725 then CHAR(39) || JSON_EXTRACT(data, '$.EventData.SubjectUserName') || CHAR(39) || ' disabled the user ' || CHAR(39) || JSON_EXTRACT(data, '$.EventData.TargetUserName') || CHAR(39)
    WHEN eventid = 4722 then  CHAR(39) || JSON_EXTRACT(data, '$.EventData.SubjectUserName') || CHAR(39) || ' enabled the user account ' || CHAR(39) || JSON_EXTRACT(data, '$.EventData.TargetUserName') || CHAR(39)
    WHEN eventid IN ('4723','4724') then CHAR(39) || JSON_EXTRACT(data, '$.EventData.SubjectUserName') || CHAR(39) || ' reset/set the password for ' || CHAR(39) || JSON_EXTRACT(data, '$.EventData.TargetUserName') || CHAR(39)
    WHEN eventid IN ('4728','4732','4756') then CHAR(39) || JSON_EXTRACT(data, '$.EventData.SubjectUserName') || CHAR(39) || ' added ' || CHAR(39) || 
		CASE	
			WHEN (Select u.username from users u where JSON_EXTRACT(data, '$.EventData.MemberSid') = u.uuid) == '' then JSON_EXTRACT(data, '$.EventData.TargetSid') ELSE (Select u.username from users u where JSON_EXTRACT(data, '$.EventData.MemberSid') = u.uuid) 
		END 
	|| CHAR(39) || ' to the security group ' || CHAR(39) || JSON_EXTRACT(data, '$.EventData.TargetUserName') || CHAR(39)
    WHEN eventid IN ('4729','4733','4757') then CHAR(39) || JSON_EXTRACT(data, '$.EventData.SubjectUserName') || CHAR(39) || ' removed ' || CHAR(39) || 
		CASE WHEN (Select u.username from users u where JSON_EXTRACT(data, '$.EventData.MemberSid') = u.uuid) == '' then JSON_EXTRACT(data, '$.EventData.TargetSid') ELSE (Select u.username from users u where JSON_EXTRACT(data, '$.EventData.MemberSid') = u.uuid) 
		END 
	|| CHAR(39) || ' from the security group ' || CHAR(39) || JSON_EXTRACT(data, '$.EventData.TargetUserName') || CHAR(39)
    ELSE NULL
    END AS Description,
   JSON_EXTRACT(data, '$.EventData.SubjectUserName') AS 'Who_Made_The_Change',
   CAST ( (Select u.username from users u where JSON_EXTRACT(data, '$.EventData.MemberSid') = u.uuid) AS text) Username_Changed,
   JSON_EXTRACT(data, '$.EventData.MemberSid') AS 'User_SID_Changed',
   JSON_EXTRACT(data, '$.EventData.TargetUserName') AS 'Group_Or_User_Name_Changed',
   JSON_EXTRACT(data, '$.EventData.TargetSid') AS 'Group_SID_or_User_SID_Changed',
   'Security EVTX' AS Data_Source,
   'User.02.0' AS Query
FROM sophos_windows_events
WHERE source = 'Security' AND time > STRFTIME('%s','NOW','-$$days$$ DAYS') AND eventid IN ('4726', '4730', '4734', '4758', '4740','4727', '4754', '4731', '4720', '4767', '4725', '4722','4723','4724', '4728','4732','4756', '4729','4733','4757') ORDER BY Datetime DESC