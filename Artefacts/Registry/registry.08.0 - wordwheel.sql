/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Extracts and converts the hexadecimal wordsheel values from NTUSER             |
|                                                                                |
|                                                                                |
| Query Type: Endpoint                                                           |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team | Lee Kirkpatrick                              |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/


WITH RECURSIVE
  hex_conversion AS (
    SELECT
    strftime('%Y-%m-%dT%H:%M:%SZ',datetime(mtime,'unixepoch')) as ModifiedTime, 
      REPLACE(data, '00', '') AS data,
      regex_match(path, '(S-[0-9]+(-[0-9]+)+)', '') AS sid, 
      u.username 
    FROM
      registry
    LEFT JOIN users u ON sid = u.uuid
    WHERE
      key LIKE 'HKEY_USERS\%\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery'
      AND name != 'MRUListEx'
  ),
  parse_hex(data, converted_data, remaining) AS (
    SELECT
      data,
      '',
      LENGTH(data) AS remaining
    FROM
      hex_conversion
    UNION ALL
    SELECT
      data,
      converted_data || CHAR(
          (CASE SUBSTR(data, LENGTH(data) - remaining + 1, 1) 
              WHEN 'A' THEN 10 
              WHEN 'B' THEN 11 
              WHEN 'C' THEN 12 
              WHEN 'D' THEN 13 
              WHEN 'E' THEN 14 
              WHEN 'F' THEN 15 
              ELSE CAST(SUBSTR(data, LENGTH(data) - remaining + 1, 1) AS INTEGER) 
          END) * 16
          +
          (CASE SUBSTR(data, LENGTH(data) - remaining + 2, 1) 
              WHEN 'A' THEN 10 
              WHEN 'B' THEN 11 
              WHEN 'C' THEN 12 
              WHEN 'D' THEN 13 
              WHEN 'E' THEN 14 
              WHEN 'F' THEN 15 
              ELSE CAST(SUBSTR(data, LENGTH(data) - remaining + 2, 1) AS INTEGER) 
          END)
      ),
      remaining - 2
    FROM
      parse_hex
    WHERE
      remaining > 0
  )

SELECT 
   hex.ModifiedTime,
  p.data AS original_hex,
  p.converted_data AS converted_ascii,
  hex.sid,
  hex.username
FROM 
  parse_hex p
JOIN
  hex_conversion hex ON p.data = hex.data
WHERE
  p.remaining = 0;

