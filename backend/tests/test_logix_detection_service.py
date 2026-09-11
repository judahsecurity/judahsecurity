from types import SimpleNamespace

from app.services.logix_detection_service import (
    classify_keyswitch,
    detect_observation_changes,
    inspect_logix_controller,
    select_logix_candidates,
)


class FakeLogixDriver:
    instances = []

    def __init__(self, path, **kwargs):
        self.path = path
        self.kwargs = kwargs
        self.socket_timeout = None
        self.info = {
            "vendor": "Rockwell Automation/Allen-Bradley",
            "product_type": "Programmable Logic Controller",
            "product_code": 166,
            "product_name": "1756-L83E/B",
            "revision": {"major": 35, "minor": 11},
            "serial": "ABC123",
            "status": b"4\x00",
            "keyswitch": "REMOTE RUN",
            "name": "Plant_Controller",
        }
        self.inventory_called = False
        self.__class__.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def get_tag_list(self, **_kwargs):
        self.inventory_called = True
        self.info["programs"] = {"MainProgram": {}}
        self.info["tasks"] = {"MainTask": {}}
        self.info["modules"] = {"Local:1": {}}
        return [
            {
                "tag_name": "Program:MainProgram.RunCommand",
                "tag_type": "atomic",
                "data_type_name": "BOOL",
                "external_access": "Read/Write",
                "dimensions": [0, 0, 0],
                "alias": False,
                "value": "must-not-be-stored",
            }
        ]


def test_runtime_read_disables_automatic_tag_upload():
    FakeLogixDriver.instances.clear()
    result = inspect_logix_controller(
        "192.0.2.25",
        socket_timeout=3,
        driver_factory=FakeLogixDriver,
    )

    driver = FakeLogixDriver.instances[0]
    assert driver.kwargs == {"init_tags": False, "init_program_tags": False}
    assert driver.socket_timeout == 3
    assert driver.inventory_called is False
    assert result["reachable"] is True
    assert result["revision"] == "35.011"
    assert result["keyswitch"] == "REMOTE RUN"
    assert result["hard_run"] is False
    assert "tags" not in result


def test_inventory_is_explicit_and_never_stores_tag_values():
    FakeLogixDriver.instances.clear()
    result = inspect_logix_controller(
        "192.0.2.25",
        include_program_inventory=True,
        driver_factory=FakeLogixDriver,
    )

    assert FakeLogixDriver.instances[0].inventory_called is True
    assert result["programs"] == ["MainProgram"]
    assert result["tag_count"] == 1
    assert result["inventory_hash"]
    assert "value" not in result["tags"][0]


def test_candidate_chaining_requires_logix_identity_evidence():
    generic_enip = SimpleNamespace(
        port=44818,
        state="open",
        host="192.0.2.20",
        ip="192.0.2.20",
        service_name="ethernet-ip",
        service_product=None,
        service_version=None,
        script_results={},
    )
    logix = SimpleNamespace(
        port=44818,
        state="open",
        host="192.0.2.25",
        ip="192.0.2.25",
        service_name="ethernet-ip",
        service_product="Rockwell ControlLogix",
        service_version=None,
        script_results={"enip-info": "Vendor: Rockwell Automation"},
    )

    assert select_logix_candidates([generic_enip, logix]) == ["192.0.2.25"]
    assert select_logix_candidates(
        [generic_enip], require_identity_evidence=False
    ) == ["192.0.2.20"]
    assert select_logix_candidates([logix], max_hosts=0) == []


def test_remote_program_is_distinct_high_risk_posture():
    result = classify_keyswitch("REMOTE PROGRAM")
    assert result == {
        "keyswitch": "REMOTE PROGRAM",
        "hard_run": False,
        "remote_mode": True,
        "posture": "remote_program",
    }


def test_change_detection_compares_successful_baselines_only():
    previous = {
        "reachable": True,
        "serial": "ABC123",
        "project_name": "Line_1",
        "keyswitch": "RUN",
    }
    current = {
        "reachable": True,
        "serial": "ABC123",
        "project_name": "Line_2",
        "keyswitch": "REMOTE RUN",
    }

    assert detect_observation_changes(previous, current) == [
        {"field": "project_name", "before": "Line_1", "after": "Line_2"},
        {"field": "keyswitch", "before": "RUN", "after": "REMOTE RUN"},
    ]
