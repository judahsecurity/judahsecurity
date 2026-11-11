# Blink as a Judah response executor

Judah owns intake, deduplication, analyst triage, the SLA clock, the owner
notice and the event log. Blink carries out the actions you assign to it:
emailing owners, reminders, close-out notes, tickets. It reports each result
back to Judah, so Judah stays the record of what was sent and when.

```
Sources (Judah scanners, Tenable, Wiz, HackerOne, manual, Blink adapters)
   ▼
Judah: dedup → triage queue → analyst approves → SLA date set → notice rendered
   ▼  signed webhook event (action = notify_owner / sla_reminders / close_out / open_ticket)
Blink "VR - Respond" (vr-respond.yaml): fetch notice → email / post / ticket
   ▼  POST /api/v1/finding-response/findings/{id}/actions
Judah: notified_at, ticket, reminders, breach, close-out in the event log
```

## Setup

1. **Judah API key for Blink.** Create an agent API key with scope
   `findings:respond`. Add `findings:triage` only if Blink should approve
   findings, e.g. from a Slack or Teams approval step. Store the key as the
   Blink secret `judah_api_key`.
2. **Import `vr-respond.yaml`.** Create the workflow and its custom webhook
   trigger. Copy the trigger URL and API key. Resolve the `VERIFY` markers
   against your catalog: the email action (Outlook/Graph/SMTP),
   Slack/Teams, and Jira.
3. **Point Judah at Blink** (admin):
   ```
   PUT /api/v1/finding-response/settings/webhook
   {"url": "<trigger URL>", "api_key_header": "BLINK-API-KEY",
    "api_key": "<trigger key>", "secret": "<optional HMAC secret>"}
   ```
4. **Choose executors** (admin). Each action has exactly one executor:
   ```
   PUT /api/v1/finding-response/settings/response
   {"executors": {"notify_owner": "webhook", "sla_reminders": "webhook",
                  "close_out": "webhook", "open_ticket": "off"},
    "judah_base_url": "https://judah.example.com",
    "default_owner_email": "vm-team@example.com"}
   ```
   `webhook` means Blink (or any webhook consumer), `judah` means Judah sends
   it itself, and `off` records the event without acting on it.
5. **SLA table** (admin). Partial updates are fine:
   ```
   PUT /api/v1/finding-response/settings/sla-policy
   {"internet_accessible": {"urgent": 2, "critical": 14, "high": 30, "medium": 60, "low": 90},
    "non_internet_accessible": {"urgent": 10, "critical": 30, "high": 60, "medium": 90, "low": 180}}
   ```

6. **Notice wording** (admin, optional). The notice combines the finding
   template and the "External Exposure" letter. Labels, date format, intro,
   closing paragraphs and the contact team are all settings:
   ```
   PUT /api/v1/finding-response/settings/response
   {"notice": {"date_format": "%B %d, %Y",
               "labels": {"severity": "Criticality", "asset": "Impacted Asset",
                          "remediation_date": "Required Remediation Date"},
               "contact_name": "Vulnerability Management",
               "contact_email": "vm-team@example.com",
               "intro_template": "On {detected_date}, an {exposure} vulnerability was identified ... within {sla_days} days ...",
               "closing_templates": ["If this issue has been remediated, please contact the {contact} team."]}}
   ```
   At triage, analysts set `owner_team` (the "To:" line), `finding_type`
   (the "Type:" line, inferred when omitted), and any missing notice text
   (`edits.impact`, `edits.steps_to_reproduce`, ...). The notice JSON lists
   `missing_fields` so a workflow can hold back incomplete notices.

## Event payload

```json
{
  "event_id": 42, "event_type": "owner_notice", "action": "notify_owner",
  "organization_id": 1, "occurred_at": "2026-11-10T12:00:00", "actor": "analyst@example.com",
  "finding": {
    "id": 7, "title": "Expired SSL Certificate", "severity": "high", "sla_tier": "high",
    "internet_accessible": true, "sla_days": 30, "remediation_due": "12/10/2026",
    "asset": "www.sure-start.com", "owner_email": "owner@example.com", "sources": ["nuclei", "wiz"],
    "links": {"notice_json": ".../notice?format=json", "notice_docx": ".../notice?format=docx",
              "actions_callback": ".../actions"}
  },
  "details": {"sla": {"tier": "high", "days": 30, "due_at": "2026-12-10T12:00:00"}}
}
```

Headers: `X-Judah-Event`, `X-Judah-Event-Id`, `X-Judah-Timestamp`, plus the
configured API key header. When a secret is set, `X-Judah-Signature` is
`sha256=HMAC(secret, "<timestamp>.<raw body>")`.

Event types that carry an action:

| event_type | action | when |
|---|---|---|
| `owner_notice` | `notify_owner` | analyst approves at triage |
| `sla_warning` | `sla_reminders` | 50% and 90% of the window (configurable) |
| `sla_breached` | `sla_reminders` | deadline passed (once) |
| `resolved` | `close_out` | finding resolved / accepted / mitigated / false positive |

Failed deliveries retry with backoff, up to 8 attempts. An event that was
delivered but never reported back stays `delivered` in the finding's event
log (`GET /finding-response/findings/{id}`).

## Blink adapters

The adapters in the Blink vulnerability-response package can keep pulling
from Censys, Praetorian, Falcon and the ratings vendors. Point them at
Judah's ingestion API instead of the Blink "Process Finding" subflow, so
deduplication happens in one place.
