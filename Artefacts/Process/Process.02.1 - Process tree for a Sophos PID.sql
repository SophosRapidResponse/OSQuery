/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Displays the process tree for a specified Sophos PID                           |
|                                                                                |
| VARIABLES                                                                      |
| sophos_pid (sophosPID)                                                         |
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
        sid,
        parent_sophos_pid
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
    sid,
    parent_sophos_pid
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
        process_journal.sid,
        process_journal.parent_sophos_pid
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
        process_journal.sid,
        process_journal.parent_sophos_pid
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
        child.sid,
        child.parent_sophos_pid
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
    ordered_tree.parent_sophos_pid,
    ordered_tree.sha256
FROM ordered_tree
LEFT JOIN users ON
    users.uuid LIKE ordered_tree.sid
GROUP BY
    ordered_tree.sophos_pid
ORDER BY
    ordered_tree.row_number