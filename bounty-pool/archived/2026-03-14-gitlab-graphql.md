# GitLab — GraphQL Security Issues

**Target:** gitlab.com
**Program:** GitLab Bug Bounty (HackerOne)
**Scan Date:** 2026-03-14
**Status:** PENDING REVIEW — LOW PROBABILITY

## Findings

### 1. GraphQL Introspection Enabled (3,613 types exposed)
- **Severity:** Medium
- **CWE:** CWE-200 (Information Exposure)
- **Asset:** https://www.gitlab.com/api/graphql
- **Evidence:** POST with `{"query": "{__schema{types{name}}}"}` returns full schema
- **41+ sensitive mutations exposed** including adminSidekiqQueuesDeleteJobs, adminRolesLdapSync
- **BUT:** GitLab's API is public by design. Their docs reference GraphQL. This is likely "working as intended."
- **Recommendation:** Probably informative/not applicable. Only submit if GitLab explicitly states introspection should be disabled.

### 2. GraphQL No Query Depth Limit (DoS Risk)
- **Severity:** Medium
- **CWE:** CWE-400 (Uncontrolled Resource Consumption)
- **Asset:** https://www.gitlab.com/api/graphql
- **Evidence:** Nested queries 10+ levels deep return valid data
- **BUT:** GitLab likely has internal complexity analysis and rate limiting.
- **Recommendation:** Worth probing deeper. Try a 20+ level nested query and see if it causes measurable slowdown.

### 3. CORS Wildcard on /api/v1 — FALSE POSITIVE (FIXED)
- This was `ACAO: *` without `credentials: true` — browser won't send cookies
- **SecBot fix applied:** CORS check now correctly skips wildcard-without-credentials preflight

## Assessment
- Both GraphQL findings are technically correct but likely "informative" for GitLab
- GitLab has one of the most mature security programs — they know their API is public
- **Recommendation:** Don't submit unless we can demonstrate actual impact (e.g., query that causes measurable DoS)
- The CORS finding was a SecBot FP that has been fixed

## Raw Evidence
See: validation-run-8/gitlab/secbot-2026-03-14T10-36-04-191Z-bounty.md
