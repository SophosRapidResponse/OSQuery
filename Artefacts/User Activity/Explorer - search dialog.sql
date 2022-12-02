/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                     |
| List all terms put into the File Explorer search dialog                         |
|                                                                                 |
| IMPORTANT                                                                       |
| The query was configured to decodes up to 60 characters from HEX to ASCII.      |
| In case the result is bigger than 60 characters the analyst should use a tool   |
| such as Cyberchef to transform the HEX value to ASCII.                          |
|                                                                                 |
| LOCATION                                                                        |
| NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery    |                                                                               |
|                                                                                 |
| VARIABLE                                                                        |
| - username (type: STRING)                                                       |
| - user_sid (type: STRING)                                                       |
|                                                                                 |
| If you want to bring back everything use % for username/user_sid                |
|                                                                                 |
| Version: 1.0                                                                    |
| Author: The Rapid Response Team | Karl Ackerman                                 |
| github.com/SophosRapidResponse                                                  |
\*********************************************************************************/


WITH RECURSIVE RegKeys(mtime,Path, Data, sid, number) AS (
    SELECT 
      mtime, 
      Path, 
      REPLACE(data,'00',''), 
      regex_match(path,'(S-[0-9]+(-[0-9]+)+)', '') AS sid, 
      row_number() OVER() 
    FROM REGISTRY 
    WHERE path LIKE 'HKEY_USERS\%\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery\%'),

Sequence(x) AS (VALUES ( 1 ) UNION ALL SELECT x+1 FROM Sequence WHERE x < (SELECT MAX(number) FROM RegKeys))

SELECT
   'WordWheelQuery' AS subkey,
   datetime((SELECT mtime FROM Regkeys WHERE number = x),'unixepoch') modified_time,
   (SELECT Path FROM Regkeys WHERE number = x) Reg_Path, 
   (SELECT data FROM Regkeys WHERE number = x) Reg_Value, 
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),1,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),3,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),5,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),7,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),9,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),11,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),13,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),15,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),17,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),19,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),21,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),23,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),25,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),27,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),29,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),31,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),33,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),35,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),37,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),39,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),41,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),43,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),45,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),47,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),49,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),51,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),53,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),55,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),57,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),59,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),61,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),63,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),65,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),67,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),69,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),71,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),73,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),75,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),77,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),79,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),81,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),83,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),85,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),87,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),89,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),91,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),93,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),95,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),97,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),99,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),101,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),103,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),105,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),107,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),109,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),111,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),113,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),115,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),117,2))||
   (SELECT CHAR(int) FROM hex_to_int WHERE hex_string = '0x'||substring((Select Data from RegKeys WHERE number = x),119,2))
   AS Reg_ASCII,
   CAST ((SELECT sid FROM Regkeys WHERE number = x) AS TEXT) Reg_sid,
   CAST(u.username AS TEXT) username 
FROM Sequence, RegKeys
LEFT JOIN  users u ON Reg_sid = u.uuid
WHERE username LIKE '$$user$$' 
   AND Reg_sid LIKE '$$user_sid$$'
GROUP BY Reg_Path, Reg_Value, Reg_ASCII