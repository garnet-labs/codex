-- Cross-repository form of the hunts in ../hunts.md.
--
-- `export_actions.sql` flattens one repository's profiles into a file. These
-- queries ask the same questions of every repository the platform recorded, over
-- pull-request runs only, which is where third-party code reaches CI.
--
-- Read-only, against the jibril read replica through the Cloud SQL proxy:
--
--   PGOPTIONS='-c default_transaction_read_only=on -c statement_timeout=300s' \
--     psql "host=127.0.0.1 port=5433 user=<you> dbname=jibril sslmode=disable" \
--     -v days=30 -v label=crypto_miner_execution \
--     -f .garnet/tools/hunt.sql
--
-- Every query is scoped by :days. Query 3 is scoped by :label.

\echo '== 1. detection labels on pull-request runs, by volume and spread'

WITH action AS (
  SELECT p.github_org || '/' || p.repo          AS repository,
         p.run_id,
         p.job,
         jsonb_array_elements_text(peer->'detections') AS label
  FROM profiles p
  JOIN agents a ON a.id = p.agent_id
  LEFT JOIN github_context gc ON gc.id = a.context_id AND a.kind = 'github'
  CROSS JOIN LATERAL jsonb_array_elements(p.data->'network'->'egress'->'peers') AS peer
  WHERE p.created_at > now() - (:'days' || ' days')::interval
    AND gc.event_name = 'pull_request'
)
SELECT label,
       count(*)                    AS actions,
       count(DISTINCT repository)  AS repositories,
       count(DISTINCT run_id)      AS runs
FROM action
WHERE label <> 'flow'
GROUP BY label
ORDER BY repositories, actions DESC;

\echo ''
\echo '== 2. the same labels, ranked by rarity: fewest repositories first'
\echo '   (a label in one repository is either that repository is special, or the'
\echo '    label is. Both are worth a look; neither is a verdict.)'

WITH action AS (
  SELECT p.github_org || '/' || p.repo          AS repository,
         jsonb_array_elements_text(peer->'detections') AS label
  FROM profiles p
  JOIN agents a ON a.id = p.agent_id
  LEFT JOIN github_context gc ON gc.id = a.context_id AND a.kind = 'github'
  CROSS JOIN LATERAL jsonb_array_elements(p.data->'network'->'egress'->'peers') AS peer
  WHERE p.created_at > now() - (:'days' || ' days')::interval
    AND gc.event_name = 'pull_request'
)
SELECT label,
       count(DISTINCT repository) AS repositories,
       count(*)                   AS actions,
       string_agg(DISTINCT repository, ', ') AS which
FROM action
WHERE label <> 'flow'
GROUP BY label
HAVING count(DISTINCT repository) <= 3
ORDER BY repositories, actions DESC;

\echo ''
\echo '== 3. drill into one label: chain, destination, step, and a linkable profile'

SELECT p.github_org || '/' || p.repo                        AS repository,
       gc.workflow,
       p.job,
       gc.actor,
       left(coalesce(nullif(gc.sha, ''), p.github_sha), 10) AS commit,
       array_to_string(
         ARRAY(SELECT jsonb_array_elements_text(tree->'ancestry')), ' > ')
         || ' -> ' || coalesce(peer->'remote_names'->>0, peer->>'remote_address')
                                                            AS execution_chain,
       nullif(tree->>'github_step', '')                     AS step,
       array_to_string(
         ARRAY(SELECT jsonb_array_elements_text(peer->'detections')), ',')
                                                            AS labels,
       'https://app.garnet.ai/public/runs/' || p.run_id || '?profile=' || p.id
                                                            AS profile_url
FROM profiles p
JOIN agents a ON a.id = p.agent_id
LEFT JOIN github_context gc ON gc.id = a.context_id AND a.kind = 'github'
CROSS JOIN LATERAL jsonb_array_elements(p.data->'network'->'egress'->'peers') AS peer
CROSS JOIN LATERAL jsonb_array_elements(peer->'proc_trees') AS tree
WHERE p.created_at > now() - (:'days' || ' days')::interval
  AND gc.event_name = 'pull_request'
  AND peer->'detections' ? :'label'
ORDER BY p.created_at DESC
LIMIT 50;

\echo ''
\echo '== 4. destinations a repository/job reached in its newest recorded run and'
\echo '      not in the run before it (the comparison a reviewer wants, per job)'

WITH job_run AS (
  SELECT p.github_org || '/' || p.repo AS repository,
         p.job,
         p.run_id,
         max(p.created_at)             AS recorded_at,
         row_number() OVER (
           PARTITION BY p.github_org || '/' || p.repo, p.job
           ORDER BY max(p.created_at) DESC
         )                             AS recency
  FROM profiles p
  JOIN agents a ON a.id = p.agent_id
  LEFT JOIN github_context gc ON gc.id = a.context_id AND a.kind = 'github'
  WHERE p.created_at > now() - (:'days' || ' days')::interval
    AND gc.event_name = 'pull_request'
  GROUP BY 1, 2, 3
), dest AS (
  SELECT jr.repository,
         jr.job,
         jr.recency,
         jr.run_id,
         coalesce(peer->'remote_names'->>0, peer->>'remote_address') AS destination
  FROM job_run jr
  JOIN profiles p ON p.run_id = jr.run_id AND p.job = jr.job
  CROSS JOIN LATERAL jsonb_array_elements(p.data->'network'->'egress'->'peers') AS peer
  WHERE jr.recency <= 2
)
SELECT newest.repository,
       newest.job,
       newest.run_id AS newest_run,
       newest.destination AS destination_only_in_newest_run
FROM dest newest
WHERE newest.recency = 1
  AND NOT EXISTS (
        SELECT 1 FROM dest previous
        WHERE previous.recency = 2
          AND previous.repository = newest.repository
          AND previous.job = newest.job
          AND previous.destination = newest.destination
      )
GROUP BY 1, 2, 3, 4
ORDER BY 1, 2, 4;
