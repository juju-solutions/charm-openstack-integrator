from configparser import ConfigParser
import pytest


@pytest.fixture
def credentials():
    yield {"openstack": {}}


@pytest.fixture
def credentials_cnf(tmpdir, credentials):
    config = ConfigParser()
    config.read_dict(credentials)
    path = tmpdir.join("test.cnf")
    with open(path, "w") as file:
        config.write(file)

    yield path.strpath
