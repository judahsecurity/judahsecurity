"""
Enhanced Wappalyzer integration service for technology fingerprinting.

This service implements comprehensive technology detection following the official
Wappalyzer specification (https://github.com/tomnomnom/wappalyzer).

Detection methods supported:
- HTTP headers
- HTML content patterns
- Meta tags
- Cookies
- Script sources (scriptSrc)
- Inline scripts content
- DOM element patterns
- JavaScript variables (via inline script analysis)
- URL patterns
- CSS patterns
- robots.txt patterns

Also supports:
- implies/requires/excludes relationships
- Confidence scoring
- Version extraction with ternary operators
- External fingerprint loading from Wappalyzer JSON files
"""

from __future__ import annotations

import re
import json
import logging
import os
from typing import Optional, Dict, List, Any, Set
from dataclasses import dataclass, field
from pathlib import Path

import httpx
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


@dataclass
class DetectedTechnology:
    """A detected technology."""
    name: str
    slug: str
    confidence: int = 100
    version: Optional[str] = None
    categories: list[str] = field(default_factory=list)
    website: Optional[str] = None
    icon: Optional[str] = None
    cpe: Optional[str] = None
    description: Optional[str] = None
    # Implied technologies (from the 'implies' field)
    implied_by: Optional[str] = None


def slugify(name: str) -> str:
    """Convert technology name to URL-safe slug."""
    slug = name.lower()
    slug = re.sub(r'[^a-z0-9]+', '-', slug)
    slug = slug.strip('-')
    return slug


def parse_pattern_with_tags(pattern: str) -> tuple[str, int, Optional[str]]:
    """
    Parse a Wappalyzer pattern string and extract tags.
    
    Wappalyzer patterns can include tags like:
    - `;confidence:50` - confidence level
    - `;version:\\1` - version extraction
    
    Args:
        pattern: Pattern string possibly containing tags
        
    Returns:
        Tuple of (regex_pattern, confidence, version_template)
    """
    confidence = 100
    version_template = None
    
    # Split on \; to find tags
    parts = pattern.split('\\;')
    regex_pattern = parts[0]
    
    for part in parts[1:]:
        if part.startswith('confidence:'):
            try:
                confidence = int(part.split(':')[1])
            except (ValueError, IndexError):
                pass
        elif part.startswith('version:'):
            version_template = part.split(':', 1)[1] if ':' in part else None
    
    return regex_pattern, confidence, version_template


def extract_version(match: re.Match, version_template: Optional[str]) -> Optional[str]:
    """
    Extract version from regex match using Wappalyzer version syntax.
    
    Supports:
    - \\1 - Returns first capture group
    - \\1?a: - Returns 'a' if match, nothing otherwise
    - \\1?a:b - Returns 'a' if match, 'b' otherwise
    - \\1?:b - Returns nothing if match, 'b' otherwise
    - foo\\1 - Returns 'foo' + first capture group
    
    Args:
        match: Regex match object
        version_template: Version template string
        
    Returns:
        Extracted version or None
    """
    if not version_template:
        if match.groups():
            return match.group(1) if match.group(1) else None
        return None
    
    version = version_template
    
    # Handle ternary operators: \\1?a:b
    ternary_pattern = r'\\\\(\d)\?([^:]*):([^\\]*)'
    for m in re.finditer(ternary_pattern, version):
        group_num = int(m.group(1))
        if_true = m.group(2)
        if_false = m.group(3)
        
        try:
            group_value = match.group(group_num) if group_num <= len(match.groups()) else None
            replacement = if_true if group_value else if_false
            version = version.replace(m.group(0), replacement)
        except IndexError:
            version = version.replace(m.group(0), if_false)
    
    # Handle simple group references: \\1
    for i in range(len(match.groups()), 0, -1):
        placeholder = f'\\\\{i}'
        try:
            value = match.group(i) or ''
            version = version.replace(placeholder, value)
        except IndexError:
            version = version.replace(placeholder, '')
    
    return version.strip() if version.strip() else None


# =============================================================================
# Extended Technology Fingerprints
# =============================================================================
# Based on official Wappalyzer patterns from:
# https://github.com/tomnomnom/wappalyzer/tree/master/src/technologies

TECHNOLOGY_FINGERPRINTS = {
    # -------------------------------------------------------------------------
    # CMS Platforms
    # -------------------------------------------------------------------------
    "WordPress": {
        "cats": ["CMS", "Blog"],
        "headers": {"X-Powered-By": r"WordPress", "Link": r"<[^>]+wp-json"},
        "meta": {"generator": r"WordPress(?:\s([\d.]+))?\\;version:\\1"},
        "html": [r"wp-content/(?:themes|plugins)/", r"wp-includes/"],
        "scriptSrc": [r"/wp-(?:content|includes)/"],
        "cookies": {"wordpress_logged_in": "", "wp-settings": ""},
        "icon": "WordPress.svg",
        "website": "https://wordpress.org",
        "cpe": "cpe:2.3:a:wordpress:wordpress",
        "implies": ["PHP", "MySQL"],
        "description": "WordPress is a free and open-source content management system."
    },
    "Drupal": {
        "cats": ["CMS"],
        "headers": {
            "X-Drupal-Cache": "",
            "X-Drupal-Dynamic-Cache": "",
            "X-Generator": r"Drupal(?:\s([\d.]+))?\\;version:\\1"
        },
        "meta": {"generator": r"Drupal(?:\s([\d.]+))?\\;version:\\1"},
        "html": [r"drupal\.js", r"Drupal\.settings", r"sites/(?:default|all)/"],
        "scriptSrc": [r"/sites/(?:default|all)/"],
        "icon": "Drupal.svg",
        "website": "https://drupal.org",
        "cpe": "cpe:2.3:a:drupal:drupal",
        "implies": ["PHP"],
        "description": "Drupal is a free and open-source CMS."
    },
    "Joomla": {
        "cats": ["CMS"],
        "meta": {"generator": r"Joomla!?(?:\s([\d.]+))?\\;version:\\1"},
        "html": [
            r"/media/jui/",
            r"/media/system/js/",
            r"<script[^>]+/media/system/",
            r"Joomla\.(?:Text|Lang)"
        ],
        "headers": {"X-Content-Encoded-By": r"Joomla!?(?:\s([\d.]+))?\\;version:\\1"},
        "icon": "Joomla.svg",
        "website": "https://joomla.org",
        "cpe": "cpe:2.3:a:joomla:joomla",
        "implies": ["PHP"],
        "description": "Joomla is a free and open-source CMS."
    },
    "Typo3": {
        "cats": ["CMS"],
        "meta": {"generator": r"TYPO3(?:\s([\d.]+))?\\;version:\\1"},
        "html": [r"typo3(?:conf|temp)/", r"t3lib/", r"fileadmin/"],
        "scriptSrc": [r"typo3(?:conf|temp)/"],
        "headers": {"X-TYPO3-Parsetime": ""},
        "icon": "TYPO3.svg",
        "website": "https://typo3.org",
        "implies": ["PHP"],
    },
    "Contentful": {
        "cats": ["CMS"],
        "html": [r"contentful\.com", r"ctfassets\.net"],
        "scriptSrc": [r"contentful"],
        "icon": "Contentful.svg",
        "website": "https://contentful.com",
    },
    "Ghost": {
        "cats": ["CMS", "Blog"],
        "meta": {"generator": r"Ghost(?:\s([\d.]+))?\\;version:\\1"},
        "headers": {"X-Ghost-Cache-Status": ""},
        "html": [r"ghost-(?:url|version)", r"/ghost/"],
        "icon": "Ghost.svg",
        "website": "https://ghost.org",
    },
    "Wix": {
        "cats": ["CMS", "Ecommerce"],
        "html": [r"wix\.com", r"wixstatic\.com", r"_wix_browser_sess"],
        "meta": {"generator": r"Wix\.com Website Builder"},
        "headers": {"X-Wix-Request-Id": ""},
        "icon": "Wix.svg",
        "website": "https://wix.com",
    },
    "Squarespace": {
        "cats": ["CMS", "Ecommerce"],
        "html": [r"squarespace\.com", r"static\.squarespace\.com"],
        "headers": {"X-ServedBy": r"squarespace"},
        "icon": "Squarespace.svg",
        "website": "https://squarespace.com",
    },
    "Webflow": {
        "cats": ["CMS"],
        "html": [r"webflow\.com", r"uploads-ssl\.webflow\.com"],
        "meta": {"generator": r"Webflow"},
        "headers": {"X-Powered-By": r"Webflow"},
        "icon": "Webflow.svg",
        "website": "https://webflow.com",
    },
    "HubSpot CMS": {
        "cats": ["CMS"],
        "html": [r"hs-scripts\.com", r"hubspot\.com"],
        "headers": {"X-HubSpot-Correlation-Id": ""},
        "icon": "HubSpot.svg",
        "website": "https://hubspot.com",
    },
    "Adobe Experience Manager": {
        "cats": ["CMS"],
        "html": [r"/etc\.clientlibs/", r"/content/dam/", r"cq\.shared\.clientlibs"],
        "cookies": {"cq-authoring-mode": ""},
        "icon": "Adobe.svg",
        "website": "https://adobe.com/marketing/experience-manager.html",
        "cpe": "cpe:2.3:a:adobe:experience_manager",
    },
    "Sitecore": {
        "cats": ["CMS"],
        "html": [r"sitecore", r"/sitecore/"],
        "cookies": {"SC_ANALYTICS_GLOBAL_COOKIE": "", "sitecore": ""},
        "headers": {"X-Powered-By": r"Sitecore"},
        "icon": "Sitecore.svg",
        "website": "https://sitecore.com",
    },
    
    # -------------------------------------------------------------------------
    # Web Servers
    # -------------------------------------------------------------------------
    "Nginx": {
        "cats": ["Web servers"],
        "headers": {"Server": r"nginx(?:/([\d.]+))?\\;version:\\1"},
        "icon": "Nginx.svg",
        "website": "https://nginx.org",
        "cpe": "cpe:2.3:a:nginx:nginx"
    },
    "Apache": {
        "cats": ["Web servers"],
        "headers": {"Server": r"Apache(?:/([\d.]+))?\\;version:\\1"},
        "icon": "Apache.svg",
        "website": "https://apache.org",
        "cpe": "cpe:2.3:a:apache:http_server"
    },
    "Microsoft IIS": {
        "cats": ["Web servers"],
        "headers": {"Server": r"Microsoft-IIS(?:/([\d.]+))?\\;version:\\1"},
        "icon": "Microsoft.svg",
        "website": "https://www.iis.net",
        "cpe": "cpe:2.3:a:microsoft:iis"
    },
    "LiteSpeed": {
        "cats": ["Web servers"],
        "headers": {"Server": r"LiteSpeed"},
        "icon": "LiteSpeed.svg",
        "website": "https://litespeedtech.com"
    },
    "Caddy": {
        "cats": ["Web servers"],
        "headers": {"Server": r"Caddy"},
        "icon": "Caddy.svg",
        "website": "https://caddyserver.com",
    },
    "OpenResty": {
        "cats": ["Web servers"],
        "headers": {"Server": r"openresty(?:/([\d.]+))?\\;version:\\1"},
        "website": "https://openresty.org",
        "implies": ["Nginx", "Lua"],
    },
    
    # -------------------------------------------------------------------------
    # Programming Languages
    # -------------------------------------------------------------------------
    "PHP": {
        "cats": ["Programming languages"],
        "headers": {"X-Powered-By": r"PHP(?:/([\d.]+))?\\;version:\\1", "Server": r"PHP(?:/([\d.]+))?"},
        "cookies": {"PHPSESSID": ""},
        "url": [r"\.php(?:$|\?)"],
        "icon": "PHP.svg",
        "website": "https://php.net",
        "cpe": "cpe:2.3:a:php:php"
    },
    "Python": {
        "cats": ["Programming languages"],
        "headers": {"X-Powered-By": r"Python(?:/([\d.]+))?\\;version:\\1"},
        "icon": "Python.svg",
        "website": "https://python.org",
    },
    "Ruby": {
        "cats": ["Programming languages"],
        "headers": {"X-Powered-By": r"Phusion Passenger", "Server": r"Phusion Passenger"},
        "icon": "Ruby.svg",
        "website": "https://ruby-lang.org",
    },
    "Java": {
        "cats": ["Programming languages"],
        "headers": {"X-Powered-By": r"Servlet|JSP"},
        "cookies": {"JSESSIONID": ""},
        "icon": "Java.svg",
        "website": "https://java.com",
    },
    "Node.js": {
        "cats": ["Programming languages"],
        "headers": {"X-Powered-By": r"Express|Node\.js"},
        "icon": "Node.js.svg",
        "website": "https://nodejs.org",
    },
    "ASP.NET": {
        "cats": ["Programming languages", "Web frameworks"],
        "headers": {"X-AspNet-Version": r"([\d.]+)\\;version:\\1", "X-Powered-By": r"ASP\.NET"},
        "cookies": {"ASP.NET_SessionId": "", "ASPSESSIONID": ""},
        "html": [r"__VIEWSTATE"],
        "icon": "Microsoft.svg",
        "website": "https://dotnet.microsoft.com/apps/aspnet",
        "cpe": "cpe:2.3:a:microsoft:asp.net"
    },
    "Go": {
        "cats": ["Programming languages"],
        "headers": {"X-Powered-By": r"Go"},
        "icon": "Go.svg",
        "website": "https://go.dev",
    },
    "Lua": {
        "cats": ["Programming languages"],
        "headers": {"X-Powered-By": r"Lua"},
        "icon": "Lua.svg",
        "website": "https://lua.org",
    },
    
    # -------------------------------------------------------------------------
    # JavaScript Frameworks
    # -------------------------------------------------------------------------
    "React": {
        "cats": ["JavaScript frameworks"],
        "html": [r"data-react(?:root|id)", r"__REACT_DEVTOOLS_GLOBAL_HOOK__"],
        "scriptSrc": [r"react(?:\.production)?(?:\.min)?\.js"],
        "scripts": [r"React\.createElement", r"ReactDOM\.render"],
        "icon": "React.svg",
        "website": "https://reactjs.org",
        "implies": ["JavaScript"],
    },
    "Vue.js": {
        "cats": ["JavaScript frameworks"],
        "html": [r"data-v-[a-f0-9]{8}", r"<[^>]+v-(?:if|for|bind|on|model|show|cloak)"],
        "scriptSrc": [r"vue(?:[.-]([\d.]+))?(?:\.min)?\.js\\;version:\\1"],
        "scripts": [r"Vue\.(?:component|mixin|directive|filter|use)"],
        "icon": "Vue.js.svg",
        "website": "https://vuejs.org",
        "implies": ["JavaScript"],
    },
    "Angular": {
        "cats": ["JavaScript frameworks"],
        "html": [r"<[^>]+ng-(?:app|controller|model|view)", r"ng-version=\"([\d.]+)\"\\;version:\\1"],
        "scriptSrc": [r"angular(?:[.-]([\d.]+))?(?:\.min)?\.js\\;version:\\1"],
        "scripts": [r"angular\.module"],
        "icon": "Angular.svg",
        "website": "https://angular.io",
        "implies": ["JavaScript"],
    },
    "AngularJS": {
        "cats": ["JavaScript frameworks"],
        "html": [r"ng-app=", r"ng-controller=", r"ng-model="],
        "scriptSrc": [r"angular(?:[.-]?([\d.]+))?(?:\.min)?\.js\\;version:\\1"],
        "scripts": [r"angular\.(?:bootstrap|module)"],
        "icon": "AngularJS.svg",
        "website": "https://angularjs.org",
        "implies": ["JavaScript"],
    },
    "Svelte": {
        "cats": ["JavaScript frameworks"],
        "scripts": [r"__svelte"],
        "html": [r"svelte-[a-z0-9]+"],
        "icon": "Svelte.svg",
        "website": "https://svelte.dev",
    },
    "Ember.js": {
        "cats": ["JavaScript frameworks"],
        "html": [r"data-ember-action", r"ember-view"],
        "scriptSrc": [r"ember(?:\.min)?\.js"],
        "scripts": [r"Ember\.Application"],
        "icon": "Ember.js.svg",
        "website": "https://emberjs.com",
    },
    "Backbone.js": {
        "cats": ["JavaScript frameworks"],
        "scriptSrc": [r"backbone(?:\.min)?\.js"],
        "scripts": [r"Backbone\.(?:Model|View|Collection)"],
        "icon": "Backbone.js.svg",
        "website": "https://backbonejs.org",
    },
    "Alpine.js": {
        "cats": ["JavaScript frameworks"],
        "html": [r"x-data=", r"x-bind:", r"x-on:"],
        "scriptSrc": [r"alpine(?:\.min)?\.js"],
        "icon": "Alpine.js.svg",
        "website": "https://alpinejs.dev",
    },
    "Preact": {
        "cats": ["JavaScript frameworks"],
        "scriptSrc": [r"preact(?:\.min)?\.js"],
        "scripts": [r"preact\.(?:h|render|Component)"],
        "icon": "Preact.svg",
        "website": "https://preactjs.com",
    },
    "Solid": {
        "cats": ["JavaScript frameworks"],
        "scripts": [r"_\$HY"],
        "icon": "Solid.svg",
        "website": "https://solidjs.com",
    },
    "HTMX": {
        "cats": ["JavaScript frameworks"],
        "html": [r"hx-(?:get|post|put|delete|patch|trigger|target|swap)"],
        "scriptSrc": [r"htmx(?:\.min)?\.js"],
        "icon": "HTMX.svg",
        "website": "https://htmx.org",
    },
    
    # -------------------------------------------------------------------------
    # JavaScript Libraries
    # -------------------------------------------------------------------------
    "jQuery": {
        "cats": ["JavaScript libraries"],
        "scriptSrc": [r"jquery[.-]?([\d.]+)?(?:\.min)?\.js\\;version:\\1"],
        "scripts": [r"jQuery\.fn\.jquery"],
        "icon": "jQuery.svg",
        "website": "https://jquery.com",
        "cpe": "cpe:2.3:a:jquery:jquery"
    },
    "jQuery UI": {
        "cats": ["JavaScript libraries"],
        "scriptSrc": [r"jquery-ui[.-]?([\d.]+)?(?:\.min)?\.js\\;version:\\1"],
        "html": [r"ui-datepicker", r"ui-dialog", r"ui-accordion"],
        "icon": "jQuery UI.svg",
        "website": "https://jqueryui.com",
        "requires": "jQuery",
    },
    "jQuery Migrate": {
        "cats": ["JavaScript libraries"],
        "scriptSrc": [r"jquery-migrate[.-]?([\d.]+)?(?:\.min)?\.js\\;version:\\1"],
        "requires": "jQuery",
    },
    "Lodash": {
        "cats": ["JavaScript libraries"],
        "scriptSrc": [r"lodash(?:[.-]([\d.]+))?(?:\.min)?\.js\\;version:\\1"],
        "scripts": [r"_\.(?:map|filter|reduce|forEach)"],
        "icon": "Lodash.svg",
        "website": "https://lodash.com",
    },
    "Underscore.js": {
        "cats": ["JavaScript libraries"],
        "scriptSrc": [r"underscore(?:[.-]([\d.]+))?(?:\.min)?\.js\\;version:\\1"],
        "scripts": [r"_\.(?:map|filter|reduce)\\b"],
        "icon": "Underscore.js.svg",
        "website": "https://underscorejs.org",
    },
    "Moment.js": {
        "cats": ["JavaScript libraries"],
        "scriptSrc": [r"moment(?:[.-]([\d.]+))?(?:\.min)?\.js\\;version:\\1"],
        "scripts": [r"moment\("],
        "icon": "Moment.js.svg",
        "website": "https://momentjs.com",
    },
    "Day.js": {
        "cats": ["JavaScript libraries"],
        "scriptSrc": [r"dayjs(?:[.-]([\d.]+))?(?:\.min)?\.js\\;version:\\1"],
        "icon": "Day.js.svg",
        "website": "https://day.js.org",
    },
    "Axios": {
        "cats": ["JavaScript libraries"],
        "scriptSrc": [r"axios(?:[.-]([\d.]+))?(?:\.min)?\.js\\;version:\\1"],
        "scripts": [r"axios\.(?:get|post|put|delete)"],
        "icon": "Axios.svg",
        "website": "https://axios-http.com",
    },
    "D3.js": {
        "cats": ["JavaScript libraries", "JavaScript graphics"],
        "scriptSrc": [r"d3(?:[.-]v?([\d.]+))?(?:\.min)?\.js\\;version:\\1"],
        "scripts": [r"d3\.(?:select|selectAll|csv)"],
        "icon": "D3.svg",
        "website": "https://d3js.org",
    },
    "Chart.js": {
        "cats": ["JavaScript libraries", "JavaScript graphics"],
        "scriptSrc": [r"chart(?:[.-]([\d.]+))?(?:\.min)?\.js\\;version:\\1"],
        "scripts": [r"new Chart\\("],
        "icon": "Chart.js.svg",
        "website": "https://chartjs.org",
    },
    "Three.js": {
        "cats": ["JavaScript libraries", "JavaScript graphics"],
        "scriptSrc": [r"three(?:[.-]([\d.]+))?(?:\.min)?\.js\\;version:\\1"],
        "scripts": [r"THREE\.(?:Scene|Camera|Renderer)"],
        "icon": "Three.js.svg",
        "website": "https://threejs.org",
    },
    "GSAP": {
        "cats": ["JavaScript libraries"],
        "scriptSrc": [r"gsap(?:[.-]([\d.]+))?(?:\.min)?\.js\\;version:\\1", r"TweenMax"],
        "scripts": [r"gsap\.(?:to|from|fromTo)", r"TweenMax"],
        "icon": "GSAP.svg",
        "website": "https://greensock.com/gsap",
    },
    "Anime.js": {
        "cats": ["JavaScript libraries"],
        "scriptSrc": [r"anime(?:[.-]([\d.]+))?(?:\.min)?\.js\\;version:\\1"],
        "scripts": [r"anime\\("],
        "icon": "Anime.js.svg",
        "website": "https://animejs.com",
    },
    
    # -------------------------------------------------------------------------
    # Web Frameworks
    # -------------------------------------------------------------------------
    "Next.js": {
        "cats": ["Web frameworks", "Static site generator"],
        "headers": {"X-Powered-By": r"Next\.js"},
        "html": [r"/_next/", r"__NEXT_DATA__", r"__next"],
        "scriptSrc": [r"/_next/static/"],
        "icon": "Next.js.svg",
        "website": "https://nextjs.org",
        "implies": ["React", "Node.js"],
    },
    "Nuxt.js": {
        "cats": ["Web frameworks", "Static site generator"],
        "html": [r"/_nuxt/", r"__NUXT__", r"nuxt"],
        "meta": {"generator": r"Nuxt"},
        "scriptSrc": [r"/_nuxt/"],
        "icon": "Nuxt.js.svg",
        "website": "https://nuxtjs.org",
        "implies": ["Vue.js", "Node.js"],
    },
    "Gatsby": {
        "cats": ["Static site generator"],
        "meta": {"generator": r"Gatsby(?:\s([\d.]+))?\\;version:\\1"},
        "html": [r"gatsby-", r"__gatsby"],
        "scriptSrc": [r"/gatsby-"],
        "icon": "Gatsby.svg",
        "website": "https://gatsbyjs.com",
        "implies": ["React", "Node.js"],
    },
    "SvelteKit": {
        "cats": ["Web frameworks"],
        "html": [r"__sveltekit"],
        "scriptSrc": [r"/_app/"],
        "icon": "SvelteKit.svg",
        "website": "https://kit.svelte.dev",
        "implies": ["Svelte"],
    },
    "Remix": {
        "cats": ["Web frameworks"],
        "html": [r"__remixContext"],
        "scripts": [r"__remixContext"],
        "icon": "Remix.svg",
        "website": "https://remix.run",
        "implies": ["React"],
    },
    "Astro": {
        "cats": ["Web frameworks", "Static site generator"],
        "meta": {"generator": r"Astro(?:\sv?([\d.]+))?\\;version:\\1"},
        "html": [r"astro-island", r"astro-slot"],
        "icon": "Astro.svg",
        "website": "https://astro.build",
    },
    "Express": {
        "cats": ["Web frameworks"],
        "headers": {"X-Powered-By": r"Express"},
        "icon": "Express.svg",
        "website": "https://expressjs.com",
        "implies": ["Node.js"],
    },
    "Fastify": {
        "cats": ["Web frameworks"],
        "headers": {"X-Powered-By": r"Fastify"},
        "icon": "Fastify.svg",
        "website": "https://fastify.io",
        "implies": ["Node.js"],
    },
    "Koa": {
        "cats": ["Web frameworks"],
        "headers": {"X-Powered-By": r"Koa"},
        "website": "https://koajs.com",
        "implies": ["Node.js"],
    },
    "Laravel": {
        "cats": ["Web frameworks"],
        "cookies": {"laravel_session": "", "XSRF-TOKEN": ""},
        "headers": {"X-Powered-By": r"Laravel"},
        "html": [r"laravel"],
        "icon": "Laravel.svg",
        "website": "https://laravel.com",
        "implies": ["PHP"],
    },
    "Symfony": {
        "cats": ["Web frameworks"],
        "cookies": {"symfony": ""},
        "headers": {"X-Debug-Token": "", "X-Symfony-Cache": ""},
        "html": [r"_profiler"],
        "icon": "Symfony.svg",
        "website": "https://symfony.com",
        "implies": ["PHP"],
    },
    "Django": {
        "cats": ["Web frameworks"],
        "cookies": {"csrftoken": "", "django_language": ""},
        "html": [r"csrfmiddlewaretoken", r"__admin_media_prefix__"],
        "icon": "Django.svg",
        "website": "https://djangoproject.com",
        "implies": ["Python"],
    },
    "Flask": {
        "cats": ["Web frameworks"],
        "cookies": {"session": "eyJ"},  # Flask session cookies start with eyJ (base64 encoded JSON)
        "headers": {"X-Powered-By": r"Flask"},
        "icon": "Flask.svg",
        "website": "https://flask.palletsprojects.com",
        "implies": ["Python"],
    },
    "FastAPI": {
        "cats": ["Web frameworks"],
        "html": [r"fastapi", r"/docs", r"/redoc"],
        "website": "https://fastapi.tiangolo.com",
        "implies": ["Python"],
    },
    "Ruby on Rails": {
        "cats": ["Web frameworks"],
        "headers": {"X-Powered-By": r"Phusion Passenger", "Server": r"Phusion Passenger"},
        "cookies": {"_session_id": ""},
        "meta": {"csrf-param": r"authenticity_token"},
        "html": [r"data-turbo", r"csrf-token"],
        "icon": "Ruby on Rails.svg",
        "website": "https://rubyonrails.org",
        "implies": ["Ruby"],
    },
    "Spring": {
        "cats": ["Web frameworks"],
        "cookies": {"JSESSIONID": ""},
        "headers": {"X-Application-Context": ""},
        "html": [r"org\.springframework"],
        "icon": "Spring.svg",
        "website": "https://spring.io",
        "implies": ["Java"],
    },
    "ASP.NET Core": {
        "cats": ["Web frameworks"],
        "headers": {"X-Powered-By": r"ASP\.NET Core", "X-AspNetCore-Version": r"([\d.]+)\\;version:\\1"},
        "icon": "Microsoft.svg",
        "website": "https://dotnet.microsoft.com/apps/aspnet",
    },
    
    # -------------------------------------------------------------------------
    # UI Frameworks & CSS
    # -------------------------------------------------------------------------
    "Bootstrap": {
        "cats": ["UI frameworks"],
        "html": [r"<link[^>]+bootstrap(?:[.-]([\d.]+))?(?:\.min)?\.css\\;version:\\1"],
        "scriptSrc": [r"bootstrap(?:[.-]([\d.]+))?(?:\.min)?\.js\\;version:\\1"],
        "icon": "Bootstrap.svg",
        "website": "https://getbootstrap.com"
    },
    "Tailwind CSS": {
        "cats": ["UI frameworks"],
        "html": [
            r'class="[^"]*(?:sm:|md:|lg:|xl:|2xl:)',
            r'class="[^"]*(?:flex|grid|block|inline|hidden)',
            r'class="[^"]*(?:bg-|text-|border-|rounded-|shadow-|p-|m-|w-|h-)'
        ],
        "icon": "Tailwind CSS.svg",
        "website": "https://tailwindcss.com"
    },
    "Bulma": {
        "cats": ["UI frameworks"],
        "html": [r'class="[^"]*(?:is-|has-)[^"]*"', r"bulma(?:[.-]([\d.]+))?(?:\.min)?\.css\\;version:\\1"],
        "scriptSrc": [r"bulma"],
        "icon": "Bulma.svg",
        "website": "https://bulma.io",
    },
    "Foundation": {
        "cats": ["UI frameworks"],
        "html": [r"<link[^>]+foundation", r'class="[^"]*(?:small-|medium-|large-)[0-9]'],
        "scriptSrc": [r"foundation(?:[.-]([\d.]+))?(?:\.min)?\.js\\;version:\\1"],
        "icon": "ZURB.svg",
        "website": "https://get.foundation",
    },
    "Material-UI": {
        "cats": ["UI frameworks"],
        "html": [r"MuiButton", r"MuiTypography", r"MuiBox"],
        "scriptSrc": [r"@mui/material"],
        "icon": "Material UI.svg",
        "website": "https://mui.com",
        "implies": ["React"],
    },
    "Ant Design": {
        "cats": ["UI frameworks"],
        "html": [r'class="[^"]*ant-[^"]*"'],
        "scriptSrc": [r"antd"],
        "icon": "Ant Design.svg",
        "website": "https://ant.design",
        "implies": ["React"],
    },
    "Chakra UI": {
        "cats": ["UI frameworks"],
        "html": [r"chakra-"],
        "scriptSrc": [r"@chakra-ui"],
        "icon": "Chakra UI.svg",
        "website": "https://chakra-ui.com",
        "implies": ["React"],
    },
    "Semantic UI": {
        "cats": ["UI frameworks"],
        "html": [r'class="[^"]*ui[^"]*(?:button|form|container|segment)"'],
        "scriptSrc": [r"semantic(?:[.-]([\d.]+))?(?:\.min)?\.js\\;version:\\1"],
        "icon": "Semantic UI.svg",
        "website": "https://semantic-ui.com",
    },
    "Materialize CSS": {
        "cats": ["UI frameworks"],
        "html": [r'class="[^"]*(?:materialize-|waves-)'],
        "scriptSrc": [r"materialize(?:[.-]([\d.]+))?(?:\.min)?\.js\\;version:\\1"],
        "icon": "Materialize CSS.svg",
        "website": "https://materializecss.com",
    },
    
    # -------------------------------------------------------------------------
    # Ecommerce Platforms
    # -------------------------------------------------------------------------
    "Shopify": {
        "cats": ["Ecommerce"],
        "headers": {"X-ShopId": "", "X-Shopify-Stage": ""},
        "html": [r"cdn\.shopify\.com", r"Shopify\.theme", r"myshopify\.com"],
        "scriptSrc": [r"cdn\.shopify\.com"],
        "icon": "Shopify.svg",
        "website": "https://shopify.com"
    },
    "WooCommerce": {
        "cats": ["Ecommerce"],
        "meta": {"generator": r"WooCommerce(?:\s([\d.]+))?\\;version:\\1"},
        "html": [r"woocommerce", r"wc-", r"wc_add_to_cart"],
        "scriptSrc": [r"woocommerce"],
        "icon": "WooCommerce.svg",
        "website": "https://woocommerce.com",
        "requires": "WordPress",
    },
    "Magento": {
        "cats": ["Ecommerce"],
        "cookies": {"frontend": "", "mage-messages": ""},
        "html": [r"/skin/frontend/", r"Mage\.Cookies", r"mage/cookies", r"magento"],
        "scriptSrc": [r"mage/", r"Magento"],
        "icon": "Magento.svg",
        "website": "https://magento.com",
        "cpe": "cpe:2.3:a:magento:magento",
        "implies": ["PHP", "MySQL"],
    },
    "PrestaShop": {
        "cats": ["Ecommerce"],
        "meta": {"generator": r"PrestaShop"},
        "html": [r"prestashop", r"/themes/default-bootstrap/"],
        "cookies": {"PrestaShop-": ""},
        "icon": "PrestaShop.svg",
        "website": "https://prestashop.com",
        "implies": ["PHP", "MySQL"],
    },
    "OpenCart": {
        "cats": ["Ecommerce"],
        "html": [r"catalog/view/theme", r"route=common/home"],
        "cookies": {"OCSESSID": ""},
        "icon": "OpenCart.svg",
        "website": "https://opencart.com",
        "implies": ["PHP"],
    },
    "BigCommerce": {
        "cats": ["Ecommerce"],
        "html": [r"bigcommerce", r"cdn\.bcapp\.dev"],
        "headers": {"X-BC-Request-Id": ""},
        "scriptSrc": [r"bigcommerce"],
        "icon": "BigCommerce.svg",
        "website": "https://bigcommerce.com",
    },
    "Salesforce Commerce Cloud": {
        "cats": ["Ecommerce"],
        "html": [r"demandware\.store", r"salesforce-commerce-cloud"],
        "cookies": {"dwsid": ""},
        "icon": "Salesforce.svg",
        "website": "https://salesforce.com/products/commerce-cloud",
    },
    
    # -------------------------------------------------------------------------
    # Analytics & Tag Managers
    # -------------------------------------------------------------------------
    "Google Analytics": {
        "cats": ["Analytics"],
        "html": [r"google-analytics\.com/(?:ga|analytics)\.js", r"googletagmanager\.com/gtag/js"],
        "scriptSrc": [r"google-analytics\.com", r"googletagmanager\.com/gtag"],
        "scripts": [r"GoogleAnalyticsObject", r"gtag\\("],
        "icon": "Google Analytics.svg",
        "website": "https://google.com/analytics"
    },
    "Google Tag Manager": {
        "cats": ["Tag managers"],
        "html": [r"googletagmanager\.com/gtm\.js", r"GTM-[A-Z0-9]+"],
        "scriptSrc": [r"googletagmanager\.com/gtm\.js"],
        "icon": "Google Tag Manager.svg",
        "website": "https://tagmanager.google.com"
    },
    "Google Analytics 4": {
        "cats": ["Analytics"],
        "html": [r"gtag/js\?id=G-", r"G-[A-Z0-9]+"],
        "scriptSrc": [r"gtag/js"],
        "scripts": [r"gtag\\("],
        "icon": "Google Analytics.svg",
        "website": "https://google.com/analytics",
    },
    "Hotjar": {
        "cats": ["Analytics"],
        "html": [r"static\.hotjar\.com", r"hotjar\.com/c/hotjar"],
        "scriptSrc": [r"hotjar\.com"],
        "scripts": [r"hj\\("],
        "icon": "Hotjar.svg",
        "website": "https://hotjar.com"
    },
    "Segment": {
        "cats": ["Analytics"],
        "html": [r"cdn\.segment\.com/analytics\.js"],
        "scriptSrc": [r"cdn\.segment\.com"],
        "scripts": [r"analytics\\.(?:page|track|identify)"],
        "icon": "Segment.svg",
        "website": "https://segment.com",
    },
    "Mixpanel": {
        "cats": ["Analytics"],
        "html": [r"cdn\.mxpnl\.com"],
        "scriptSrc": [r"mixpanel"],
        "scripts": [r"mixpanel\\.(?:track|identify)"],
        "icon": "Mixpanel.svg",
        "website": "https://mixpanel.com",
    },
    "Heap": {
        "cats": ["Analytics"],
        "html": [r"cdn\.heapanalytics\.com"],
        "scriptSrc": [r"heapanalytics"],
        "icon": "Heap.svg",
        "website": "https://heap.io",
    },
    "Amplitude": {
        "cats": ["Analytics"],
        "html": [r"cdn\.amplitude\.com"],
        "scriptSrc": [r"amplitude"],
        "scripts": [r"amplitude\\.(?:logEvent|setUserId)"],
        "icon": "Amplitude.svg",
        "website": "https://amplitude.com",
    },
    "Plausible": {
        "cats": ["Analytics"],
        "scriptSrc": [r"plausible\.io/js/plausible"],
        "icon": "Plausible.svg",
        "website": "https://plausible.io",
    },
    "Matomo": {
        "cats": ["Analytics"],
        "html": [r"piwik\.js", r"matomo\.js"],
        "scriptSrc": [r"(?:piwik|matomo)\.js"],
        "scripts": [r"_paq\.push"],
        "icon": "Matomo.svg",
        "website": "https://matomo.org",
    },
    "Facebook Pixel": {
        "cats": ["Analytics"],
        "html": [r"connect\.facebook\.net/[^/]+/fbevents\.js"],
        "scriptSrc": [r"connect\.facebook\.net"],
        "scripts": [r"fbq\\("],
        "icon": "Facebook.svg",
        "website": "https://facebook.com/business/help/952192354843755",
    },
    "LinkedIn Insight Tag": {
        "cats": ["Analytics"],
        "html": [r"snap\.licdn\.com/li\.lms-analytics/insight\.min\.js"],
        "scriptSrc": [r"licdn\.com"],
        "icon": "LinkedIn.svg",
        "website": "https://linkedin.com",
    },
    "Twitter Analytics": {
        "cats": ["Analytics"],
        "html": [r"static\.ads-twitter\.com/uwt\.js"],
        "scriptSrc": [r"ads-twitter\.com"],
        "icon": "Twitter.svg",
        "website": "https://business.twitter.com",
    },
    "Microsoft Clarity": {
        "cats": ["Analytics"],
        "html": [r"clarity\.ms/tag/"],
        "scriptSrc": [r"clarity\.ms"],
        "scripts": [r"clarity\\("],
        "icon": "Microsoft.svg",
        "website": "https://clarity.microsoft.com",
    },
    "FullStory": {
        "cats": ["Analytics"],
        "html": [r"fullstory\.com"],
        "scriptSrc": [r"fullstory\.com"],
        "scripts": [r"FS\\.(?:identify|event)"],
        "icon": "FullStory.svg",
        "website": "https://fullstory.com",
    },
    
    # -------------------------------------------------------------------------
    # CDN & Infrastructure
    # -------------------------------------------------------------------------
    "Cloudflare": {
        "cats": ["CDN", "Security"],
        "headers": {"CF-RAY": "", "Server": r"cloudflare", "CF-Cache-Status": ""},
        "cookies": {"__cfduid": "", "__cf_bm": ""},
        "icon": "CloudFlare.svg",
        "website": "https://cloudflare.com"
    },
    "Amazon Web Services": {
        "cats": ["PaaS", "IaaS"],
        "headers": {"X-Amz-Cf-Id": "", "X-Amz-Request-Id": "", "X-Amz-Id-2": ""},
        "html": [r"\.amazonaws\.com", r"s3\.amazonaws\.com", r"s3-[a-z0-9-]+\.amazonaws\.com"],
        "icon": "Amazon Web Services.svg",
        "website": "https://aws.amazon.com"
    },
    "Amazon CloudFront": {
        "cats": ["CDN"],
        "headers": {"X-Amz-Cf-Id": "", "X-Amz-Cf-Pop": "", "Via": r"cloudfront"},
        "icon": "Amazon Web Services.svg",
        "website": "https://aws.amazon.com/cloudfront",
    },
    "Amazon S3": {
        "cats": ["Cloud storage"],
        "headers": {"X-Amz-Request-Id": ""},
        "html": [r"s3\.amazonaws\.com", r"s3-[a-z0-9-]+\.amazonaws\.com"],
        "icon": "Amazon Web Services.svg",
        "website": "https://aws.amazon.com/s3",
    },
    "Akamai": {
        "cats": ["CDN"],
        "headers": {"X-Akamai-Transformed": "", "X-Akamai-Session-Info": ""},
        "html": [r"akamaihd\.net", r"akamai\.net", r"akamaitech\.net"],
        "icon": "Akamai.svg",
        "website": "https://akamai.com"
    },
    "Fastly": {
        "cats": ["CDN"],
        "headers": {"X-Served-By": r"cache-", "X-Fastly-Request-Id": "", "Fastly-Debug-Digest": ""},
        "icon": "Fastly.svg",
        "website": "https://fastly.com"
    },
    "Varnish": {
        "cats": ["Caching"],
        "headers": {"Via": r"varnish", "X-Varnish": "", "X-Varnish-Cache": ""},
        "icon": "Varnish.svg",
        "website": "https://varnish-cache.org",
        "cpe": "cpe:2.3:a:varnish-cache:varnish"
    },
    "Azure": {
        "cats": ["PaaS", "IaaS"],
        "headers": {"X-Azure-Ref": "", "X-MS-Request-Id": ""},
        "html": [r"\.azurewebsites\.net", r"\.azure\.com"],
        "icon": "Azure.svg",
        "website": "https://azure.microsoft.com",
    },
    "Google Cloud": {
        "cats": ["PaaS", "IaaS"],
        "headers": {"X-Cloud-Trace-Context": ""},
        "html": [r"\.googleapis\.com", r"storage\.googleapis\.com"],
        "icon": "Google Cloud.svg",
        "website": "https://cloud.google.com",
    },
    "Vercel": {
        "cats": ["PaaS", "CDN"],
        "headers": {"X-Vercel-Id": "", "X-Vercel-Cache": "", "Server": r"Vercel"},
        "html": [r"\.vercel\.app"],
        "icon": "Vercel.svg",
        "website": "https://vercel.com",
    },
    "Netlify": {
        "cats": ["PaaS", "CDN"],
        "headers": {"X-NF-Request-Id": "", "Server": r"Netlify"},
        "html": [r"\.netlify\.app", r"netlify\.com"],
        "icon": "Netlify.svg",
        "website": "https://netlify.com",
    },
    "Heroku": {
        "cats": ["PaaS"],
        "headers": {"Via": r"heroku", "X-Request-Id": ""},
        "html": [r"\.herokuapp\.com"],
        "icon": "Heroku.svg",
        "website": "https://heroku.com",
    },
    "DigitalOcean": {
        "cats": ["IaaS"],
        "html": [r"\.digitaloceanspaces\.com"],
        "icon": "DigitalOcean.svg",
        "website": "https://digitalocean.com",
    },
    "Render": {
        "cats": ["PaaS"],
        "headers": {"X-Render-Origin-Server": ""},
        "html": [r"\.onrender\.com"],
        "icon": "Render.svg",
        "website": "https://render.com",
    },
    "Railway": {
        "cats": ["PaaS"],
        "html": [r"\.railway\.app"],
        "website": "https://railway.app",
    },
    "Fly.io": {
        "cats": ["PaaS"],
        "headers": {"Fly-Request-Id": ""},
        "html": [r"\.fly\.dev"],
        "icon": "Fly.io.svg",
        "website": "https://fly.io",
    },
    
    # -------------------------------------------------------------------------
    # Security
    # -------------------------------------------------------------------------
    "HSTS": {
        "cats": ["Security"],
        "headers": {"Strict-Transport-Security": ""},
        "website": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
    },
    "Content Security Policy": {
        "cats": ["Security"],
        "headers": {"Content-Security-Policy": "", "Content-Security-Policy-Report-Only": ""},
        "website": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
    },
    "X-Frame-Options": {
        "cats": ["Security"],
        "headers": {"X-Frame-Options": ""},
        "website": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
    },
    "reCAPTCHA": {
        "cats": ["Security"],
        "html": [r"google\.com/recaptcha", r"grecaptcha"],
        "scriptSrc": [r"recaptcha", r"google\.com/recaptcha"],
        "icon": "reCAPTCHA.svg",
        "website": "https://google.com/recaptcha"
    },
    "hCaptcha": {
        "cats": ["Security"],
        "html": [r"hcaptcha\.com", r"h-captcha"],
        "scriptSrc": [r"hcaptcha\.com"],
        "icon": "hCaptcha.svg",
        "website": "https://hcaptcha.com",
    },
    "Imperva": {
        "cats": ["Security", "CDN"],
        "headers": {"X-Iinfo": "", "X-CDN": r"Imperva"},
        "cookies": {"incap_ses_": "", "visid_incap_": ""},
        "icon": "Imperva.svg",
        "website": "https://imperva.com",
    },
    "Sucuri": {
        "cats": ["Security"],
        "headers": {"X-Sucuri-ID": "", "Server": r"Sucuri"},
        "icon": "Sucuri.svg",
        "website": "https://sucuri.net",
    },
    "Wordfence": {
        "cats": ["Security"],
        "html": [r"wordfence", r"wfacp_"],
        "cookies": {"wfvt_": ""},
        "icon": "Wordfence.svg",
        "website": "https://wordfence.com",
        "requires": "WordPress",
    },
    "ModSecurity": {
        "cats": ["Security"],
        "headers": {"Server": r"mod_security"},
        "icon": "ModSecurity.svg",
        "website": "https://modsecurity.org",
    },
    "Okta": {
        "cats": ["Security", "Authentication"],
        "html": [r"okta\.com"],
        "cookies": {"okta-oauth-": ""},
        "icon": "Okta.svg",
        "website": "https://okta.com",
    },
    "Auth0": {
        "cats": ["Security", "Authentication"],
        "html": [r"auth0\.com", r"cdn\.auth0\.com"],
        "scriptSrc": [r"auth0"],
        "icon": "Auth0.svg",
        "website": "https://auth0.com",
    },
    "OneLogin": {
        "cats": ["Security", "Authentication"],
        "html": [r"onelogin\.com"],
        "icon": "OneLogin.svg",
        "website": "https://onelogin.com",
    },
    
    # -------------------------------------------------------------------------
    # Payment Processors
    # -------------------------------------------------------------------------
    "Stripe": {
        "cats": ["Payment processors"],
        "html": [r"js\.stripe\.com"],
        "scriptSrc": [r"stripe\.com"],
        "scripts": [r"Stripe\\("],
        "icon": "Stripe.svg",
        "website": "https://stripe.com"
    },
    "PayPal": {
        "cats": ["Payment processors"],
        "html": [r"paypal\.com/sdk/js", r"paypalobjects\.com"],
        "scriptSrc": [r"paypal\.com", r"paypalobjects\.com"],
        "icon": "PayPal.svg",
        "website": "https://paypal.com"
    },
    "Square": {
        "cats": ["Payment processors"],
        "html": [r"squareup\.com", r"square\.site"],
        "scriptSrc": [r"squareup\.com"],
        "icon": "Square.svg",
        "website": "https://squareup.com",
    },
    "Braintree": {
        "cats": ["Payment processors"],
        "html": [r"braintree"],
        "scriptSrc": [r"braintreegateway\.com"],
        "icon": "Braintree.svg",
        "website": "https://braintreepayments.com",
    },
    "Klarna": {
        "cats": ["Payment processors", "Buy now pay later"],
        "html": [r"klarna\.com"],
        "scriptSrc": [r"klarna"],
        "icon": "Klarna.svg",
        "website": "https://klarna.com",
    },
    "Affirm": {
        "cats": ["Payment processors", "Buy now pay later"],
        "html": [r"affirm\.com"],
        "scriptSrc": [r"affirm"],
        "icon": "Affirm.svg",
        "website": "https://affirm.com",
    },
    "Afterpay": {
        "cats": ["Payment processors", "Buy now pay later"],
        "html": [r"afterpay\.com"],
        "scriptSrc": [r"afterpay"],
        "icon": "Afterpay.svg",
        "website": "https://afterpay.com",
    },
    
    # -------------------------------------------------------------------------
    # Live Chat & Support
    # -------------------------------------------------------------------------
    "Intercom": {
        "cats": ["Live chat"],
        "html": [r"intercom-app", r"widget\.intercom\.io", r"intercomSettings", r"Intercom\\("],
        "scriptSrc": [r"intercom", r"widget\.intercom\.io"],
        "icon": "Intercom.svg",
        "website": "https://intercom.com"
    },
    "Zendesk": {
        "cats": ["Live chat", "Helpdesk"],
        "html": [r"ZendeskChat", r"static\.zdassets\.com", r"zendesk", r"zopim"],
        "scriptSrc": [r"zdassets\.com", r"zopim"],
        "icon": "Zendesk.svg",
        "website": "https://zendesk.com"
    },
    "Drift": {
        "cats": ["Live chat"],
        "html": [r"drift-widget", r"drift\.com", r"js\.driftt\.com"],
        "scriptSrc": [r"drift\.com", r"driftt\.com"],
        "scripts": [r"drift\\.(?:load|on)"],
        "icon": "Drift.svg",
        "website": "https://drift.com",
    },
    "Crisp": {
        "cats": ["Live chat"],
        "html": [r"crisp-chat", r"crisp\.chat"],
        "scriptSrc": [r"client\.crisp\.chat"],
        "scripts": [r"\\$crisp"],
        "icon": "Crisp.svg",
        "website": "https://crisp.chat",
    },
    "Tawk.to": {
        "cats": ["Live chat"],
        "html": [r"tawkto", r"embed\.tawk\.to"],
        "scriptSrc": [r"tawk\.to"],
        "scripts": [r"Tawk_API"],
        "icon": "tawk.to.svg",
        "website": "https://tawk.to",
    },
    "LiveChat": {
        "cats": ["Live chat"],
        "html": [r"livechat-widget", r"cdn\.livechatinc\.com", r"LiveChatWidget"],
        "scriptSrc": [r"livechatinc\.com"],
        "icon": "LiveChat.svg",
        "website": "https://livechat.com",
    },
    "Freshdesk": {
        "cats": ["Helpdesk"],
        "html": [r"freshdesk\.com"],
        "cookies": {"_fw_crm": ""},
        "icon": "Freshworks.svg",
        "website": "https://freshdesk.com",
    },
    "Freshchat": {
        "cats": ["Live chat"],
        "html": [r"wchat\.freshchat\.com"],
        "scriptSrc": [r"freshchat"],
        "icon": "Freshworks.svg",
        "website": "https://freshchat.com",
    },
    "HelpScout": {
        "cats": ["Live chat", "Helpdesk"],
        "html": [r"beacon-v2\.helpscout\.net"],
        "scriptSrc": [r"helpscout\.net"],
        "icon": "Help Scout.svg",
        "website": "https://helpscout.com",
    },
    
    # -------------------------------------------------------------------------
    # Marketing & CRM
    # -------------------------------------------------------------------------
    "HubSpot": {
        "cats": ["Marketing automation", "CRM"],
        "html": [r"js\.hs-scripts\.com", r"js\.hubspot\.com", r"hs-analytics\.net"],
        "scriptSrc": [r"hs-scripts\.com", r"hubspot\.com"],
        "cookies": {"hubspotutk": "", "__hstc": "", "__hssc": ""},
        "icon": "HubSpot.svg",
        "website": "https://hubspot.com"
    },
    "Salesforce": {
        "cats": ["CRM"],
        "html": [r"force\.com", r"salesforce\.com", r"\.my\.salesforce\.com"],
        "cookies": {"sfdc-stream": ""},
        "icon": "Salesforce.svg",
        "website": "https://salesforce.com"
    },
    "Marketo": {
        "cats": ["Marketing automation"],
        "html": [r"marketo\.com", r"mktoForms2"],
        "scriptSrc": [r"marketo"],
        "cookies": {"_mkto_trk": ""},
        "icon": "Marketo.svg",
        "website": "https://marketo.com",
    },
    "Mailchimp": {
        "cats": ["Marketing automation", "Email"],
        "html": [r"mailchimp\.com", r"list-manage\.com", r"mc\.us"],
        "scriptSrc": [r"mailchimp"],
        "icon": "Mailchimp.svg",
        "website": "https://mailchimp.com",
    },
    "Klaviyo": {
        "cats": ["Marketing automation", "Email"],
        "html": [r"klaviyo\.com"],
        "scriptSrc": [r"static\.klaviyo\.com"],
        "icon": "Klaviyo.svg",
        "website": "https://klaviyo.com",
    },
    "ActiveCampaign": {
        "cats": ["Marketing automation", "Email"],
        "html": [r"activehosted\.com", r"activecampaign\.com"],
        "scriptSrc": [r"activehosted\.com"],
        "icon": "ActiveCampaign.svg",
        "website": "https://activecampaign.com",
    },
    "Sendinblue": {
        "cats": ["Marketing automation", "Email"],
        "html": [r"sibautomation\.com", r"sendinblue\.com"],
        "scriptSrc": [r"sibautomation\.com"],
        "icon": "Sendinblue.svg",
        "website": "https://sendinblue.com",
    },
    "Pardot": {
        "cats": ["Marketing automation"],
        "html": [r"pardot\.com", r"pi\.pardot\.com"],
        "cookies": {"visitor_id": ""},
        "icon": "Salesforce.svg",
        "website": "https://pardot.com",
    },
    
    # -------------------------------------------------------------------------
    # Font & Icons
    # -------------------------------------------------------------------------
    "Font Awesome": {
        "cats": ["Font scripts"],
        "html": [r"fontawesome", r"font-awesome", r'class="fa[bsrl]?\s+fa-'],
        "scriptSrc": [r"fontawesome"],
        "icon": "Font Awesome.svg",
        "website": "https://fontawesome.com"
    },
    "Google Fonts": {
        "cats": ["Font scripts"],
        "html": [r"fonts\.googleapis\.com", r"fonts\.gstatic\.com"],
        "scriptSrc": [r"fonts\.googleapis\.com"],
        "icon": "Google.svg",
        "website": "https://fonts.google.com",
    },
    "Typekit": {
        "cats": ["Font scripts"],
        "html": [r"use\.typekit\.net", r"typekit\.com"],
        "scriptSrc": [r"typekit\.net"],
        "icon": "Adobe.svg",
        "website": "https://fonts.adobe.com",
    },
    "Adobe Fonts": {
        "cats": ["Font scripts"],
        "html": [r"use\.typekit\.net", r"fonts\.adobe\.com"],
        "scriptSrc": [r"typekit\.net"],
        "icon": "Adobe.svg",
        "website": "https://fonts.adobe.com",
    },
    "Material Icons": {
        "cats": ["Font scripts"],
        "html": [r"fonts\.googleapis\.com/icon", r'class="material-icons'],
        "icon": "Google.svg",
        "website": "https://fonts.google.com/icons",
    },
    "Ionicons": {
        "cats": ["Font scripts"],
        "html": [r"ionicons"],
        "scriptSrc": [r"ionicons"],
        "icon": "Ionicons.svg",
        "website": "https://ionicons.com",
    },
    
    # -------------------------------------------------------------------------
    # Databases
    # -------------------------------------------------------------------------
    "MySQL": {
        "cats": ["Databases"],
        "icon": "MySQL.svg",
        "website": "https://mysql.com",
        "cpe": "cpe:2.3:a:mysql:mysql",
    },
    "PostgreSQL": {
        "cats": ["Databases"],
        "icon": "PostgreSQL.svg",
        "website": "https://postgresql.org",
        "cpe": "cpe:2.3:a:postgresql:postgresql",
    },
    "MongoDB": {
        "cats": ["Databases"],
        "icon": "MongoDB.svg",
        "website": "https://mongodb.com",
    },
    "Redis": {
        "cats": ["Databases", "Caching"],
        "headers": {"X-Redis": ""},
        "icon": "Redis.svg",
        "website": "https://redis.io",
        "cpe": "cpe:2.3:a:redis:redis"
    },
    "Elasticsearch": {
        "cats": ["Databases", "Search engines"],
        "html": [r"elasticsearch"],
        "icon": "Elasticsearch.svg",
        "website": "https://elastic.co",
    },
    "Firebase": {
        "cats": ["Databases", "PaaS"],
        "html": [r"firebaseio\.com", r"firebase\.google\.com"],
        "scriptSrc": [r"firebase"],
        "icon": "Firebase.svg",
        "website": "https://firebase.google.com",
    },
    "Supabase": {
        "cats": ["Databases", "PaaS"],
        "html": [r"supabase\.co", r"supabase\.com"],
        "scriptSrc": [r"supabase"],
        "icon": "Supabase.svg",
        "website": "https://supabase.com",
    },
    
    # -------------------------------------------------------------------------
    # Miscellaneous
    # -------------------------------------------------------------------------
    "OpenSSL": {
        "cats": ["Web server extensions"],
        "headers": {"Server": r"OpenSSL(?:/([\d.]+[a-z]?))?\\;version:\\1"},
        "icon": "OpenSSL.svg",
        "website": "https://openssl.org",
        "cpe": "cpe:2.3:a:openssl:openssl"
    },
    "mod_ssl": {
        "cats": ["Web server extensions"],
        "headers": {"Server": r"mod_ssl(?:/([\d.]+))?\\;version:\\1"},
        "icon": "Apache.svg",
        "website": "https://modssl.org"
    },
    "JavaScript": {
        "cats": ["Programming languages"],
        "website": "https://developer.mozilla.org/en-US/docs/Web/JavaScript",
    },
}


class WappalyzerService:
    """
    Service for detecting web technologies using Wappalyzer-style fingerprinting.
    
    Based on the official Wappalyzer project: https://github.com/tomnomnom/wappalyzer
    
    Supports:
    - HTTP headers detection
    - HTML pattern matching
    - Meta tag analysis
    - Cookie detection
    - Script source URL matching
    - Inline script content analysis
    - URL pattern matching
    - implies/requires/excludes relationships
    - Version extraction with ternary operators
    - Confidence scoring
    """
    
    def __init__(
        self,
        fingerprints: Optional[dict] = None,
        timeout: float = 10.0,
        user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ):
        """
        Initialize Wappalyzer service.
        
        Args:
            fingerprints: Custom technology fingerprints (defaults to built-in)
            timeout: HTTP request timeout
            user_agent: User agent for HTTP requests
        """
        self.fingerprints = fingerprints or TECHNOLOGY_FINGERPRINTS
        self.timeout = timeout
        self.user_agent = user_agent
    
    async def analyze_url(
        self,
        url: str,
        min_confidence: int = 0,
        require_html: bool = False,
    ) -> list[DetectedTechnology]:
        """
        Analyze a URL and detect technologies.
        
        Args:
            url: URL to analyze
            min_confidence: Minimum confidence (0-100) to include a technology
            require_html: If True, return [] when response has no HTML body
            
        Returns:
            List of detected technologies
        """
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                verify=False
            ) as client:
                response = await client.get(
                    url,
                    headers={"User-Agent": self.user_agent}
                )
                
                return self._analyze_response(
                    response, url,
                    min_confidence=min_confidence,
                    require_html=require_html,
                )
                
        except Exception as e:
            logger.error(f"Error analyzing {url}: {e}")
            return []
    
    def analyze_url_sync(
        self,
        url: str,
        min_confidence: int = 0,
        require_html: bool = False,
    ) -> list[DetectedTechnology]:
        """Synchronous wrapper for analyze_url."""
        import asyncio
        return asyncio.run(self.analyze_url(url, min_confidence=min_confidence, require_html=require_html))
    
    def _analyze_response(
        self,
        response: httpx.Response,
        url: str,
        min_confidence: int = 0,
        require_html: bool = False,
    ) -> list[DetectedTechnology]:
        """
        Analyze HTTP response for technologies.
        
        Args:
            response: httpx Response object
            url: Original URL
            min_confidence: Minimum confidence (0-100) to include
            require_html: If True, return [] when no HTML body
            
        Returns:
            List of detected technologies
        """
        detected: Dict[str, Dict[str, Any]] = {}
        
        # Parse HTML
        html = response.text
        content_type = (response.headers.get("content-type") or "").lower()
        has_html = "text/html" in content_type or bool(html.strip())
        if require_html and not has_html:
            return []
        headers = {k.lower(): v for k, v in response.headers.items()}
        cookies = {c.name: c.value for c in response.cookies.jar}
        
        # Parse meta tags
        meta_tags = self._extract_meta_tags(html)
        
        # Extract script sources
        script_sources = self._extract_script_sources(html)
        
        # Extract inline script content
        inline_scripts = self._extract_inline_scripts(html)
        
        # Check each technology fingerprint
        for tech_name, fingerprint in self.fingerprints.items():
            confidence = 0
            version = None
            
            # Skip if requires/requiresCategory not met
            if not self._check_requirements(fingerprint, detected):
                continue
            
            # Check headers
            if "headers" in fingerprint:
                match_result = self._check_headers(headers, fingerprint["headers"])
                if match_result:
                    confidence = max(confidence, match_result["confidence"])
                    version = version or match_result.get("version")
            
            # Check HTML patterns
            if "html" in fingerprint:
                match_result = self._check_patterns(html, fingerprint["html"])
                if match_result:
                    confidence = max(confidence, match_result["confidence"])
                    version = version or match_result.get("version")
            
            # Check meta tags
            if "meta" in fingerprint:
                match_result = self._check_meta(meta_tags, fingerprint["meta"])
                if match_result:
                    confidence = max(confidence, match_result["confidence"])
                    version = version or match_result.get("version")
            
            # Check cookies
            if "cookies" in fingerprint:
                match_result = self._check_cookies(cookies, fingerprint["cookies"])
                if match_result:
                    confidence = max(confidence, match_result["confidence"])
            
            # Check script sources
            if "scriptSrc" in fingerprint:
                match_result = self._check_patterns(
                    " ".join(script_sources),
                    fingerprint["scriptSrc"]
                )
                if match_result:
                    confidence = max(confidence, match_result["confidence"])
                    version = version or match_result.get("version")
            
            # Check inline scripts content
            if "scripts" in fingerprint:
                match_result = self._check_patterns(
                    inline_scripts,
                    fingerprint["scripts"]
                )
                if match_result:
                    confidence = max(confidence, match_result["confidence"])
                    version = version or match_result.get("version")
            
            # Check URL patterns
            if "url" in fingerprint:
                match_result = self._check_patterns(url, fingerprint["url"])
                if match_result:
                    confidence = max(confidence, match_result["confidence"])
                    version = version or match_result.get("version")
            
            # If detected, add to results
            if confidence > 0:
                detected[tech_name] = {
                    "confidence": confidence,
                    "version": version,
                    "fingerprint": fingerprint,
                }
        
        # Process implies relationships
        self._process_implies(detected)
        
        # Process excludes relationships
        self._process_excludes(detected)
        
        # Build final results (filter by min_confidence)
        results = []
        for tech_name, data in detected.items():
            if data["confidence"] < min_confidence:
                continue
            fingerprint = data["fingerprint"]
            results.append(DetectedTechnology(
                name=tech_name,
                slug=slugify(tech_name),
                confidence=data["confidence"],
                version=data.get("version"),
                categories=fingerprint.get("cats", []),
                website=fingerprint.get("website"),
                icon=fingerprint.get("icon"),
                cpe=fingerprint.get("cpe"),
                description=fingerprint.get("description"),
            ))
        
        return results
    
    def _check_requirements(self, fingerprint: dict, detected: dict) -> bool:
        """Check if technology requirements are met."""
        # Check 'requires'
        requires = fingerprint.get("requires")
        if requires:
            if isinstance(requires, str):
                requires = [requires]
            for req in requires:
                if req not in detected:
                    return False
        
        # Check 'requiresCategory' (simplified - would need category mapping)
        # For now, we skip this check
        
        return True
    
    def _process_implies(self, detected: Dict[str, Dict[str, Any]]) -> None:
        """
        Process implies relationships.
        
        If Technology A implies Technology B, and A is detected,
        then B should also be added (with potentially lower confidence).
        """
        implied_to_add = {}
        
        for tech_name, data in detected.items():
            fingerprint = data["fingerprint"]
            implies = fingerprint.get("implies")
            
            if not implies:
                continue
            
            if isinstance(implies, str):
                implies = [implies]
            
            for implied in implies:
                # Parse implied tech (may include confidence)
                implied_name = implied.split("\\;")[0].strip()
                
                # Parse confidence from pattern like "PHP;confidence:50"
                implied_confidence = 50  # Default for implied
                if "\\;confidence:" in implied:
                    try:
                        conf_str = implied.split("\\;confidence:")[1].split("\\;")[0]
                        implied_confidence = int(conf_str)
                    except (ValueError, IndexError):
                        pass
                
                if implied_name in self.fingerprints and implied_name not in detected:
                    implied_to_add[implied_name] = {
                        "confidence": implied_confidence,
                        "version": None,
                        "fingerprint": self.fingerprints[implied_name],
                        "implied_by": tech_name,
                    }
        
        detected.update(implied_to_add)
    
    def _process_excludes(self, detected: Dict[str, Dict[str, Any]]) -> None:
        """
        Process excludes relationships.
        
        If Technology A excludes Technology B, and both are detected,
        remove B.
        """
        to_remove = set()
        
        for tech_name, data in detected.items():
            fingerprint = data["fingerprint"]
            excludes = fingerprint.get("excludes")
            
            if not excludes:
                continue
            
            if isinstance(excludes, str):
                excludes = [excludes]
            
            for excluded in excludes:
                if excluded in detected:
                    to_remove.add(excluded)
        
        for tech_name in to_remove:
            del detected[tech_name]
    
    def _check_headers(self, headers: dict, patterns: dict) -> Optional[dict]:
        """Check HTTP headers against patterns."""
        result = None
        
        for header_name, pattern in patterns.items():
            header_value = headers.get(header_name.lower(), "")
            if not header_value:
                continue
            
            # Parse pattern for tags
            if isinstance(pattern, str):
                regex_pattern, confidence, version_template = parse_pattern_with_tags(pattern)
            else:
                regex_pattern = pattern
                confidence = 100
                version_template = None
            
            if not regex_pattern:  # Empty pattern means just check existence
                return {"confidence": 100}
            
            try:
                match = re.search(regex_pattern, header_value, re.IGNORECASE)
            except re.error as e:
                logger.debug(f"Invalid header regex '{regex_pattern}': {e}")
                continue
            if match:
                version = extract_version(match, version_template)
                return {"confidence": confidence, "version": version}
        
        return result
    
    def _check_patterns(self, content: str, patterns: list) -> Optional[dict]:
        """Check content against regex patterns."""
        if isinstance(patterns, str):
            patterns = [patterns]
        
        for pattern in patterns:
            # Parse pattern for tags
            regex_pattern, confidence, version_template = parse_pattern_with_tags(pattern)
            
            try:
                match = re.search(regex_pattern, content, re.IGNORECASE)
                if match:
                    version = extract_version(match, version_template)
                    return {"confidence": confidence, "version": version}
            except re.error as e:
                logger.debug(f"Invalid regex pattern '{regex_pattern}': {e}")
                continue
        
        return None
    
    def _check_meta(self, meta_tags: dict, patterns: dict) -> Optional[dict]:
        """Check meta tags against patterns."""
        for meta_name, pattern in patterns.items():
            meta_value = meta_tags.get(meta_name.lower(), "")
            if not meta_value:
                continue
            
            # Parse pattern for tags
            regex_pattern, confidence, version_template = parse_pattern_with_tags(pattern)
            
            if not regex_pattern:
                return {"confidence": 100}
            
            try:
                match = re.search(regex_pattern, meta_value, re.IGNORECASE)
            except re.error as e:
                logger.debug(f"Invalid meta regex '{regex_pattern}': {e}")
                continue
            if match:
                version = extract_version(match, version_template)
                return {"confidence": confidence, "version": version}
        
        return None
    
    def _check_cookies(self, cookies: dict, patterns: dict) -> Optional[dict]:
        """Check cookies against patterns."""
        for cookie_name, pattern in patterns.items():
            # Check for cookie existence (case-insensitive)
            for name in cookies:
                if name.lower() == cookie_name.lower():
                    if not pattern:
                        return {"confidence": 100}
                    try:
                        if re.search(pattern, cookies[name], re.IGNORECASE):
                            return {"confidence": 100}
                    except re.error as e:
                        logger.debug(f"Invalid cookie regex '{pattern}': {e}")
                        continue
        return None
    
    def _extract_meta_tags(self, html: str) -> dict:
        """Extract meta tag names and content from HTML."""
        meta_tags = {}
        try:
            soup = BeautifulSoup(html, 'lxml')
            for tag in soup.find_all('meta'):
                name = tag.get('name', tag.get('property', tag.get('http-equiv', ''))).lower()
                content = tag.get('content', '')
                if name and content:
                    meta_tags[name] = content
        except Exception:
            # Fallback: regex-based extraction
            for match in re.finditer(
                r'<meta[^>]+(?:name|property)=["\']([^"\']+)["\'][^>]+content=["\']([^"\']+)["\']',
                html, re.IGNORECASE
            ):
                meta_tags[match.group(1).lower()] = match.group(2)
        return meta_tags
    
    def _extract_script_sources(self, html: str) -> list[str]:
        """Extract script src attributes from HTML."""
        sources = []
        try:
            soup = BeautifulSoup(html, 'lxml')
            for tag in soup.find_all('script', src=True):
                sources.append(tag['src'])
        except Exception:
            # Fallback: regex-based extraction
            for match in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
                sources.append(match.group(1))
        return sources
    
    def _extract_inline_scripts(self, html: str) -> str:
        """Extract inline script content from HTML."""
        scripts = []
        try:
            soup = BeautifulSoup(html, 'lxml')
            for tag in soup.find_all('script'):
                if tag.string and not tag.get('src'):
                    scripts.append(tag.string)
        except Exception:
            # Fallback: regex-based extraction
            for match in re.finditer(r'<script[^>]*>([^<]+)</script>', html, re.IGNORECASE | re.DOTALL):
                scripts.append(match.group(1))
        return "\n".join(scripts)
    
    def get_technology_categories(self, technologies: list[DetectedTechnology]) -> dict[str, list[str]]:
        """
        Group detected technologies by category.
        
        Args:
            technologies: List of detected technologies
            
        Returns:
            Dictionary mapping category names to technology names
        """
        categories = {}
        for tech in technologies:
            for cat in tech.categories:
                if cat not in categories:
                    categories[cat] = []
                categories[cat].append(tech.name)
        return categories
    
    def load_fingerprints_from_file(self, filepath: str) -> None:
        """
        Load technology fingerprints from a JSON file.
        
        This allows loading official Wappalyzer fingerprints from:
        https://github.com/wappalyzer/wappalyzer/tree/master/src/technologies
        
        Args:
            filepath: Path to JSON file
        """
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
                self.fingerprints.update(data)
                logger.info(f"Loaded {len(data)} fingerprints from {filepath}")
        except Exception as e:
            logger.error(f"Failed to load fingerprints from {filepath}: {e}")
    
    def load_fingerprints_from_directory(self, dirpath: str) -> None:
        """
        Load technology fingerprints from a directory of JSON files.
        
        Args:
            dirpath: Path to directory containing JSON files
        """
        path = Path(dirpath)
        if not path.is_dir():
            logger.error(f"Directory not found: {dirpath}")
            return
        
        for json_file in path.glob("*.json"):
            self.load_fingerprints_from_file(str(json_file))
