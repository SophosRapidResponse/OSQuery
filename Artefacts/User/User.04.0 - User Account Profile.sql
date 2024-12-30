/****************************** Sophos.com/RapidResponse ******************************\
| DESCRIPTION                                                                          |
| The query gets the creation time for when a user account profile is created on disk. |
| The account profile is usually created when the user signs in to a computer for the  |
| first time.                                                                          |
|                                                                                      |
|                                                                                      |
|  VARIABLE                                                                            |
| - username (STRING)                                                                  |
|                                                                                      |
| Version: 1.0                                                                         |
| Author: The Rapid Response Team | Bill Kearney & Elida Leite                         |
| github.com/SophosRapidResponse                                                       |
\**************************************************************************************/

SELECT
    (select datetime(btime,'unixepoch') from file f where f.path = users.directory) AS Profile_creation,
    users.directory AS User_profile,
    users.username,
    users.uuid AS SID,
    users.type,
    'File/Users' AS Data_Source,
    'User Account Profile' AS Query
FROM users
WHERE users.username LIKE '$$username$$'
   AND users.directory !=''






