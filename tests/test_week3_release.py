import netcontrol.app as app_module
from netcontrol.version import APP_VERSION


def test_fastapi_metadata_uses_shared_app_version():
    assert app_module.app.version == APP_VERSION
