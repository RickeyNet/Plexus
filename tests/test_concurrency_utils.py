from Firewall_converter.FortiGateToFTDTool.concurrency_utils import is_transient_error


def test_is_transient_error_detects_ftd_lock_timeout_patterns() -> None:
    msg = 'HTTP 423: {"messages":[{"description":"Unable to acquire the read-lock due to timeout","code":"lockTimeout"}]}'
    assert is_transient_error(msg) is True


def test_is_transient_error_returns_false_for_non_transient_validation() -> None:
    msg = 'HTTP 422: Validation failed: missing required field name'
    assert is_transient_error(msg) is False
