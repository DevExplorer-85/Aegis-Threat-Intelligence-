# Chapter 15 — Multi-Tenant Case Management

Chapter 15 adds a tenant-scoped incident case workflow to Aegis. Open `/cases` from the main navigation or a threat event card. Organization administration is available at `/admin/ops?tab=orgs` (also `/moderation?tab=orgs`). Existing Chapter 13/14 routes remain in place.

## API

- `GET /api/cases/me` — visible cases plus the active workspace and membership role.
- `GET /api/cases?status_filter=Open&q=...` — cases visible to the caller in the caller's organization.
- `POST /api/cases` — create a case with title, description, severity, optional assignee and linked feed event/threat report.
- `GET /api/cases/{case_id}`, `PATCH /api/cases/{case_id}`, `DELETE /api/cases/{case_id}` — tenant-scoped case operations.
- `GET /api/cases/org/members` — active members in the caller's organization.
- `POST /api/cases/org/members` — organization-admin provisioning of an existing user into that tenant.
- `GET /api/moderation/organisations` — platform-admin aggregate organization/member/case/refusal counts. It never returns case content.
- `POST /api/moderation/organisations` and `POST /api/moderation/organisations/{organization_id}/members` — platform-admin provisioning.

All case routes require a bearer token. Existing users are provisioned with a private organization on first Chapter 15 request; organization names are display labels and are never used to join tenants. Platform administrators still operate inside their own tenant for case APIs.

## Organization roles

- `org_admin`: read all organization cases, create/update/delete cases, assign to active organization members.
- `case_manager`: read and update organization cases, assign to active organization members; cannot delete or administer memberships.
- `member`: read cases they created or are assigned to, create cases, and update status on visible cases.

Statuses are `Open`, `In Progress`, and `Closed`; severities are `low`, `medium`, `high`, and `critical`. Every query and mutation includes `organization_id` in its MongoDB selector. Unknown or cross-tenant cases return 404 to avoid leaking their existence. Event links are checked against `feed_events`; threat report links are checked against `threat_reports`.

## Rate limits and analytics

Case reads are limited to 120 requests per minute per user and writes to 30 per minute. Responses include `X-RateLimit-Limit` and `X-RateLimit-Remaining`; rejections return 429 and `Retry-After` plus the real limit/retry values in the response detail. Refusals are recorded for aggregate admin reporting. Organization analytics contain only tenant identifiers, names, status, and aggregate counts, never case descriptions, linked threat details, or investigation notes.

## Local use

Start the backend and MongoDB using the repository's usual development flow. Demo accounts: `admin@cti.platform` / `admin123` and `analyst@cti.platform` / `analyst123`. Public registration always receives the regular `soc_analyst` platform role; organization roles are separately scoped and provisioned.
