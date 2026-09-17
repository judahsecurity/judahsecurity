import json
from urllib.parse import parse_qsl

import scanners


class DummyBridge:
    def __init__(self):
        self.urls = []
        self.flush_count = 0

    def submit_url(self, url, **metadata):
        self.urls.append((url, metadata))

    def flush(self):
        self.flush_count += 1


ROOT_HTML = """
<a href="/account">Account</a>
<form action="/send.php" method="POST">
  <input type="text" name="fullname">
  <input type="email" name="email">
  <input type="hidden" name="csrf_token" value="secret-token">
  <textarea name="message"></textarea>
  <button name="submit">Send</button>
</form>
<form action="https://outside.example/collect" method="POST">
  <input name="should_not_be_tested">
</form>
"""


def test_input_surface_builds_sanitized_pending_coverage_queue():
    pages = {
        "https://app.example/": ROOT_HTML,
        "https://app.example/account": "<html><body>No forms</body></html>",
    }
    bridge = DummyBridge()

    result = scanners.run_discover_input_surface(
        "https://app.example/",
        bridge,
        fetch_html=lambda url: pages.get(url, ""),
    )

    assert result["success"]
    assert result["forms_discovered"] == 1
    assert result["skipped_cross_origin_forms"] == 1
    form = result["forms"][0]
    assert form["action_url"] == "https://app.example/send.php"
    assert form["method"] == "POST"
    assert form["eligible_parameters"] == ["fullname", "email", "message"]
    assert form["coverage"] == {
        "fullname": "pending",
        "email": "pending",
        "message": "pending",
    }
    assert dict(parse_qsl(form["body_template"])) == {
        "fullname": "aegis",
        "email": "aegis@example.invalid",
        "message": "aegis",
    }
    assert "secret-token" not in str(result)
    assert bridge.urls[0][0] == "https://app.example/send.php"


def test_input_surface_extracts_json_fetch_template_without_execution():
    html = """
    <script>
      const jobType = document.querySelector('#job-type').value;
      fetch('/jobs', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({job_type: jobType})
      });
    </script>
    """
    bridge = DummyBridge()

    result = scanners.run_discover_input_surface(
        "https://app.example/", bridge, fetch_html=lambda _url: html
    )

    assert result["request_templates_discovered"] == 1
    request = result["request_templates"][0]
    assert request["action_url"] == "https://app.example/jobs"
    assert request["method"] == "POST"
    assert request["headers_json"] == '{"Content-Type":"application/json"}'
    assert request["body_template"] == '{"job_type":"aegis"}'
    assert request["eligible_parameters"] == ["json:job_type"]
    assert request["coverage"] == {"json:job_type": "pending"}


def test_input_surface_extracts_graphql_argument_from_template_literal():
    html = r'''<script>
      const jobType = document.querySelector('#job-type').value;
      const query = `query { jobs(jobType: "${jobType}") { id name } }`;
      fetch('/graphql/', {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({ query })
      });
    </script>'''
    result = scanners.run_discover_input_surface(
        "https://app.example/", DummyBridge(), fetch_html=lambda _url: html
    )

    request = result["request_templates"][0]
    assert request["action_url"] == "https://app.example/graphql/"
    assert request["eligible_parameters"] == ["graphql:jobType"]
    assert json.loads(request["body_template"]) == {
        "query": 'query { jobs(jobType: "aegis") { id name } }'
    }
