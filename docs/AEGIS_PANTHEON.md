# Aegis pantheon

Display names for Judah Security agent roles. Internal IDs stay snake_case;
epithets appear in fireteam prompts and debriefs.

| ID | Epithet | Vocation |
|----|---------|----------|
| orchestrator | **Joshua** | Engagement commander |
| app_mapper | Raphael | Maps apps, forms, APIs |
| web_recon | Caleb | Passive recon scout |
| content_api | Baruch | Crawl / fuzz / params |
| credential_assault | **Samson** | Default/weak credential assault |
| auth_logic | Ezra | Session / auth boundaries |
| api_authz | **Daniel** | IDOR / BOLA proof |
| host_tenant | **Judah** | Host/tenant isolation |
| business_logic | Joseph | Workflow / logic abuse |
| injection | David | SQLi / XSS / command injection |
| file_upload | Bezaleel | Upload abuse |
| saml_sso | Melchizedek | SSO / SAML / OAuth |
| spa_client | Miriam | DOM XSS / hidden routes |
| graphql_api | Nathan | GraphQL authz |
| js_secrets | Uri | JS secrets |
| secrets_hunter | Uriel | Verified credential exposure |
| cloud_audit | Nehemiah | Cloud posture |
| coverage | Nehemiah | Authenticated coverage |
| vuln_triage | Solomon | Triage without exploit |
| finding_judge | **Solomon** | Evidence judgment before publish |
| takeover | Gideon | Subdomain takeover |
| atlas / argus / hermes / janus / themis | (classical) | Existing branded tools |

Source of truth: `backend/app/services/agent/aegis_pantheon.py`.
