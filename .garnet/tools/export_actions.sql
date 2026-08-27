-- Exports one row per recorded action from the Garnet platform's stored
-- Execution Profiles for this repository.
--
-- An action here is one outbound connection: one peer of one profile, attributed
-- to one process in the execution chain that reached it. A peer reached by two
-- processes is two rows, because the two chains are different evidence.
--
-- Run against the jibril read replica through the Cloud SQL proxy:
--
--   PGOPTIONS='-c default_transaction_read_only=on -c statement_timeout=180s' \
--     psql "host=127.0.0.1 port=5433 user=<you> dbname=jibril sslmode=disable" \
--     -v org=garnet-labs -v repo=codex \
--     -At -f .garnet/tools/export_actions.sql > .garnet/evidence/actions.ndjson
SELECT jsonb_build_object(
         'repository',       coalesce(gc.repository, p.github_org || '/' || p.repo),
         'workflow',         gc.workflow,
         'job',              p.job,
         'run_id',           p.run_id,
         'run_attempt',      p.run_attempt,
         'run_url',          'https://github.com/' || coalesce(gc.repository, p.github_org || '/' || p.repo)
                             || '/actions/runs/' || p.run_id,
         'actor',            gc.actor,
         'event_name',       gc.event_name,
         'ref',              nullif(p.github_ref, ''),
         -- `commit` is the branch commit the pull request pointed at; `merge_commit`
         -- is the throwaway merge commit GitHub actually checked out for a
         -- `pull_request` run. Reviewers cite the first, reproduction needs the second.
         'commit',           coalesce(nullif(gc.sha, ''), nullif(p.github_sha, '')),
         'merge_commit',     nullif(p.github_sha, ''),
         'runner_os',        gc.runner_os,
         'runner_arch',      gc.runner_arch,
         'agent_version',    a.version,
         'recorded_at',      to_char(p.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS') || ' UTC',
         'profile_id',       p.id,
         'profile_url',      'https://app.garnet.ai/public/runs/' || p.run_id || '?profile=' || p.id,
         'action',           'outbound-connection',
         'destination',      coalesce(peer->'remote_names'->>0, peer->>'remote_address'),
         'remote_address',   peer->>'remote_address',
         'remote_port',      peer->'remote_ports'->>0,
         'protocol',         peer->>'protocol',
         'result',           peer->>'result',
         'detections',       peer->'detections',
         -- Profiles recorded by older agents carry only the chain, so the last
         -- element of the chain is the process that reached the destination.
         'process',          coalesce(
                               tree->>'process',
                               tree->'ancestry'->>(jsonb_array_length(tree->'ancestry') - 1)
                             ),
         'executable',       tree->>'executable',
         'pid',              tree->'pid',
         'execution_chain',  tree->'ancestry',
         'step',             nullif(tree->>'github_step', '')
       )
FROM profiles p
JOIN agents a ON a.id = p.agent_id
LEFT JOIN github_context gc ON gc.id = a.context_id AND a.kind = 'github'
CROSS JOIN LATERAL jsonb_array_elements(p.data->'network'->'egress'->'peers') AS peer
CROSS JOIN LATERAL jsonb_array_elements(peer->'proc_trees') AS tree
WHERE p.github_org = :'org'
  AND p.repo = :'repo'
  -- Two profiles from April 2026 are excluded: they were recorded by a
  -- `Garnet Codex CI` workflow that no longer exists in this repository, by
  -- agent 1.16.3, whose profiles carry no per-process step attribution. They
  -- are named here rather than silently dropped.
  AND coalesce(gc.workflow, '') <> 'Garnet Codex CI'
  -- Recordings from the throwaway `garnet-sensor-diag*` workflows are excluded:
  -- those jobs exist only to probe why the sensor sometimes fails to start and
  -- run no repository workload, so their egress says nothing about this CI.
  AND coalesce(gc.workflow, '') NOT LIKE 'garnet-sensor-diag%'
  -- Recordings of five commits that were earlier revisions of this branch are
  -- excluded: the branch was rewritten before review, so those commits are no
  -- longer in its history and a reader cannot follow a link back to them.
  AND coalesce(nullif(gc.sha, ''), nullif(p.github_sha, '')) NOT IN (
        '204311d983a0c7e5c7bfb9543b62abe51c6eab3a',
        '1d87e2da30dcf4e75fca1c2088dfe6e2cbacb656',
        '3aed0843f034198418f133444526a0120e267a1d',
        '882903022745af0919766b4e663eaa7170f80400',
        '5572b275881ccf7562e23e482e59a4c8094ccc1a'
      )
ORDER BY p.created_at, p.job, coalesce(peer->'remote_names'->>0, peer->>'remote_address'), tree->>'process';
