/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| This is a messy way of looking at Chrome browsing history, it does not give    |
| you the datetime the site was visited, just that the user has visted it at     |
| some point. The can be used to get a basic idea of what they have visited and  |
| if it warrents further investigation.                                          |
|                                                                                |
| VARIABLES                                                                      |
| username(string) - you must set a username, wildcards will not work here       |
|                                                                                |
| TIP                                                                            |
| You must enter a username e.g. administrator                                   |
|                                                                                |
| Version: 1.0                                                                   |
| Author: @AltShiftPrtScn & Karl the Hack Ackerman                               |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

-- Prepare a few tables that we will need to perform the hex dump
WITH RECURSIVE
   -- We want to process each character seperatly so we will create a table with a counter from 0 to the Max Bytes to dump variable
   Counter(x) AS (VALUES ( ( 0 ) ) UNION ALL SELECT x+1 FROM Counter WHERE x < 240000),

   -- DUMP the file as a LONG HEX STRING
   RAW_DUMP AS ( SELECT SUBSTR(GROUP_CONCAT(HEX(line),''),0,240000) FileBody FROM grep WHERE pattern IN (CHAR(0),CHAR(10),CHAR(32)) AND path LIKE 'C:\Users\$$username$$\AppData\Local\Google\Chrome\User Data\Default\History'),

  -- Build a single line with unprintable characters converted to CHAR(10) 'NewLine'
   CLEAN_DUMP AS ( 
   SELECT 
      GROUP_CONCAT( (SELECT CASE CAST(int AS INTEGER) BETWEEN 32 and 127 WHEN 1 THEN CHAR(int) ELSE char(10) END FROM hex_to_int WHERE hex_string = '0x'||SUBSTRING(FileBody,x*2+1, 2 )),'') Clean_Strings
   FROM Counter 
   JOIN RAW_DUMP
   WHERE HEX(substring(fileBody,x*2+1,1)) -- Just check if there is data
   ORDER BY CAST(x AS INT) ASC
   ),
   -- Create a table with all the a single String per row
   Table_of_Strings(String, Line) AS (
      SELECT '', (SELECT Clean_Strings FROM CLEAN_DUMP)||CHAR(10)
      UNION ALL 
      SELECT substr(Line, 0, instr(Line, CHAR(10) )), substr(Line, instr(Line, CHAR(10) )+1) FROM Table_of_Strings WHERE Line!=''
   )
-- last we select strings that are >= the MIN String Length and match our filter String to look for 
SELECT DISTINCT
   'Chrome' AS Source,
   '$$username$$' AS Username,
   CAST(String AS TEXT) AS Sites_Visited
FROM Table_of_Strings
WHERE LENGTH(String) > 5 AND String LIKE '%http%'
GROUP BY String 
ORDER BY String ASC

