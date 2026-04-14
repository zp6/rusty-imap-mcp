# Release tag protection setup

Releases in this repository are triggered by pushing a `v*` tag. Protect
those tags so only authorized maintainers can create them, and so the
release workflow can be gated on a review step.

## 1. Create a tag ruleset via `gh`

Run this once per repository (requires admin access):

```bash
gh api \
  --method POST \
  -H "Accept: application/vnd.github+json" \
  /repos/:owner/:repo/rulesets \
  -f name='Protect release tags' \
  -f target='tag' \
  -f enforcement='active' \
  -F 'conditions[ref_name][include][]=refs/tags/v*' \
  -F 'rules[][type]=creation' \
  -F 'rules[][type]=deletion' \
  -F 'rules[][type]=update' \
  -F 'bypass_actors[][actor_id]=<REPO_ADMIN_TEAM_ID>' \
  -F 'bypass_actors[][actor_type]=Team' \
  -F 'bypass_actors[][bypass_mode]=always'
```

Replace `:owner/:repo` and `<REPO_ADMIN_TEAM_ID>` with real values. Without a
bypass actor, even repo admins cannot push tags; with one, only members of
the designated team can.

## 2. Verify the ruleset

```bash
gh api /repos/:owner/:repo/rulesets | jq '.[] | {id, name, target, enforcement}'
```

You should see `Protect release tags` with `target: "tag"` and
`enforcement: "active"`.

## 3. Configure the `release` environment

The release workflow declares `environment: release` on the release job.
Create that environment and attach required reviewers so every tag push
waits for human approval before artifacts are published and attestations
are signed:

1. Repo -> Settings -> Environments -> New environment -> `release`.
2. Add one or more **Required reviewers** (individuals or teams).
3. Optionally scope deployment branches to `v*` tags only.

With the ruleset and the environment combined, a rogue push of a `v*` tag
is rejected at tag creation time, and if it slips past, the workflow still
blocks on reviewer approval before anything is published.
