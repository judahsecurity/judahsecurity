from local_harness.benchmark.compose_utils import container_port
from local_harness.benchmark.xss_recall import discover_targets


# --- container port parsing ------------------------------------------------

def test_bare_port():
    assert container_port("services:\n  web:\n    ports:\n      - 5000\n") == 5000


def test_host_colon_container():
    assert container_port('    ports:\n      - "8080:80"\n') == 80


def test_long_form_target():
    assert container_port("    ports:\n      - target: 3000\n        published: 0\n") == 3000


def test_default_when_absent():
    assert container_port("services: {}", default=80) == 80
    assert container_port("services: {}") is None


# --- xss endpoint/param discovery -----------------------------------------

APP_POST = """
@app.route('/')
def index(): return "x"

@app.route('/xss25', methods=['POST', 'GET'])
def xss25():
    msg = request.form.get('solution','')
    return msg
"""

APP_GET = """
@app.route('/')
def index(): return "x"

@app.route('/page')
def page():
    msg = request.args.get('name','')
    return msg
"""


def test_discover_post_form_target():
    [t] = discover_targets(APP_POST)
    assert t == {"path": "/xss25", "param": "solution", "method": "POST"}


def test_discover_get_args_target():
    [t] = discover_targets(APP_GET)
    assert t == {"path": "/page", "param": "name", "method": "GET"}


def test_index_route_skipped():
    assert all(t["path"] != "/" for t in discover_targets(APP_POST))


def test_no_param_handler_ignored():
    app = "@app.route('/health')\ndef health(): return 'ok'\n"
    assert discover_targets(app) == []
