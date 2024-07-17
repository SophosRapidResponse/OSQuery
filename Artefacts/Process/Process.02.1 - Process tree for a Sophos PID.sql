/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Shows the process tree for a Sophos PID you specify. Includes the MITRE tactic |
| and technique used in processes.                                               |
|                                                                                |
| VARIABLES                                                                      |
| sophos_pid (sophosPID) = datetime of when to start hunting                     |
|                                                                                |
| Author: Sophos MDR & Elida Leite                                               |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

WITH RECURSIVE get_ancestors(
    sophos_pid,
    level,
    start_time,
    cmd_line,
    path,
    proc_name,
    parent_sophos_pid,
    sha256,
    sid
) AS (
    SELECT
        sophos_pid,
        0 AS level,
        process_start_time,
        cmd_line,
        path,
        process_name,
        parent_sophos_pid,
        sha256,
        sid
    FROM
        sophos_process_journal
    WHERE
        sophos_pid = '$$sophos_pid$$'
    UNION
    ALL
    SELECT
        process_journal.sophos_pid,
        get_ancestors.level - 1 AS level,
        process_journal.process_start_time,
        process_journal.cmd_line,
        process_journal.path,
        process_journal.process_name,
        process_journal.parent_sophos_pid,
        process_journal.sha256,
        process_journal.sid
    FROM sophos_process_journal AS process_journal
    INNER JOIN get_ancestors ON process_journal.sophos_pid = get_ancestors.parent_sophos_pid
    ORDER BY level ASC
),
ancestor_tree AS (
    SELECT DISTINCT
        start_time,
        PRINTF('%.' || ABS(level) || 'c', '◄') || ' ' || proc_name AS process_name,
        sophos_pid,
        cmd_line,
        path,
        sha256,
        sid
    FROM get_ancestors
    WHERE
        level < 0
    ORDER BY level ASC
),
get_children(
    sophos_pid,
    level,
    start_time,
    cmd_line,
    path,
    proc_name,
    target_sophos_pid,
    sha256,
    sid
) AS (
    SELECT
        process_journal.sophos_pid,
        0 AS level,
        process_journal.process_start_time,
        process_journal.cmd_line,
        process_journal.path,
        process_journal.process_name,
        process_activity.target_sophos_pid,
        process_journal.sha256,
        process_journal.sid
    FROM sophos_process_journal AS process_journal
    LEFT JOIN sophos_process_activity AS process_activity ON
        process_activity.sophos_pid = process_journal.sophos_pid
        AND process_activity.subject = 'Process'
    WHERE
        process_journal.sophos_pid = '$$sophos_pid$$'

    UNION ALL

    SELECT
        process_journal.sophos_pid,
        get_children.level + 1 AS level,
        process_journal.process_start_time,
        process_journal.cmd_line,
        process_journal.path,
        process_journal.process_name,
        process_activity.target_sophos_pid,
        process_journal.sha256,
        process_journal.sid
    FROM sophos_process_journal AS process_journal
    INNER JOIN get_children ON
        process_journal.sophos_pid = get_children.target_sophos_pid
    LEFT JOIN sophos_process_activity AS process_activity ON
        process_activity.sophos_pid = process_journal.sophos_pid
        AND process_activity.subject = 'Process'
    ORDER BY
        level DESC
),
child_tree AS (
    SELECT DISTINCT
        child.start_time,
        CASE
            WHEN child.level = 0 THEN child.proc_name
            ELSE PRINTF('%.' || level || 'c', '►') || ' ' || child.proc_name
        END AS process_name,
        child.sophos_pid,
        child.cmd_line,
        child.path,
        child.sha256,
        child.sid
    FROM
        get_children AS child
),
tree AS (
    SELECT *
    FROM ancestor_tree
    UNION ALL
    SELECT *
    FROM child_tree
),
ordered_tree AS (
    SELECT
        ROW_NUMBER() OVER (
            ORDER BY
                (
                    SELECT NULL
                )
        ) AS row_number,
        *
    FROM tree
)
SELECT
    STRFTIME('%Y-%m-%dT%H:%M:%SZ', DATETIME(ordered_tree.start_time, 'unixepoch')) AS process_start_time,
    users.username,
    ordered_tree.sid,
    ordered_tree.process_name,
    ordered_tree.cmd_line,
    ordered_tree.path,
    ordered_tree.sophos_pid,
    ordered_tree.sha256,
    REPLACE(
        GROUP_CONCAT(
            DISTINCT(
                SELECT GROUP_CONCAT(
                    'Tactic: ' || JSON_EXTRACT(value, '$.tactic') || ' Technique: ' || JSON_EXTRACT(value, '$.technique'),
                    CHAR(10)
                )
                FROM
                    JSON_EACH(ioc.mitre_ttps)
            )
        ),
        ',',
        CHAR(10)
    ) AS mitre_ttps,
    file_properties.ml_score AS ml_score,
    file_properties.local_rep AS local_rep,
    file_properties.global_rep AS global_rep,
    file_properties.pua_score AS pua_score
FROM ordered_tree
LEFT JOIN sophos_file_properties AS file_properties USING (sha256)
LEFT JOIN users ON
    users.uuid LIKE ordered_tree.sid
LEFT JOIN sophos_runtime_ioc_journal AS ioc ON
    ioc.sophos_pid = ordered_tree.sophos_pid
    AND ioc.verbosity > 0
GROUP BY
    ordered_tree.sophos_pid
ORDER BY
    ordered_tree.row_number