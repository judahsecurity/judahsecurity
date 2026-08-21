# HTTP fingerprinting checklist (Judah)

YesWeHack recon series #3, adapted to captured Interceptor/crawl traffic
(not Caido-only). Source: https://www.yeswehack.com/learn-bug-bounty/recon-series-http-fingerprinting

## Coverage matrix

| Technique | Passive evidence | Active default |
| --- | --- | --- |
| API host discovery | sibling hosts, API path/method/content-type scores | none |
| Response headers | `Server`, `X-Powered-By`, `Via`, `CF-Ray`, API gateway `X-*` | GET / only if authorized |
| Banner / reverse proxy | explicit CDN/WAF/proxy headers | GET / only if authorized |
| Header order | Apache date→server vs nginx date→content-type→server (low confidence) | none |
| Default error pages | 403/404/500 bodies: Tomcat, Spring Boot, IIS, Nginx, Express, Django, Rails, Cloudflare, API Gateway | one random 404 if authorized |
| Malformed HTTP | unusual methods if already captured | HTTP/4.4 and XGET **not run** by default |
| Default files | `/swagger.json`, `/graphql`, `/package.json`, `/wp-json` in captured paths | HEAD those files if authorized |
| Cookies | `PHPSESSID`, `JSESSIONID`, `ASP.NET_SessionId`, `CFTOKEN` | none |
| External corroboration | **out of scope** | do not run WhatWeb/Wappalyzer/Shodan here |

Generic `nginx` / `cloudflare` / `awselb` are infrastructure, not app-framework proof.
