from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from mmdb_writer import MMDBWriter
from netaddr import IPSet

from minisiem.api import create_app
from minisiem.config import Settings
from minisiem.geo import GeoIP, describe

PUBLIC_IP = "8.8.8.8"  # an ordinary public address; the databases below are built by the tests


def _write(path, database_type, network, record):
    writer = MMDBWriter(ip_version=6, database_type=database_type, ipv4_compatible=True)
    writer.insert_network(IPSet([network]), record)
    writer.to_db_file(str(path))
    return path


@pytest.fixture
def city_db(tmp_path):
    record = {
        "country": {"iso_code": "US", "names": {"en": "United States"}},
        "city": {"names": {"en": "Mountain View"}},
    }
    return _write(tmp_path / "city.mmdb", "GeoLite2-City", "8.8.8.0/24", record)


@pytest.fixture
def asn_db(tmp_path):
    record = {"autonomous_system_number": 15169, "autonomous_system_organization": "GOOGLE"}
    return _write(tmp_path / "asn.mmdb", "GeoLite2-ASN", "8.8.8.0/24", record)


@pytest.fixture
def geo(city_db, asn_db):
    database = GeoIP.open(city_db, asn_db)
    yield database
    database.close()


def test_country_city_and_network_owner(geo):
    assert geo.lookup(PUBLIC_IP) == {
        "country_code": "US",
        "country": "United States",
        "city": "Mountain View",
        "asn": 15169,
        "org": "GOOGLE",
    }


def test_each_database_is_optional(city_db, asn_db):
    only_city = GeoIP.open(city_db)
    only_asn = GeoIP.open(None, asn_db)
    assert "asn" not in only_city.lookup(PUBLIC_IP)
    assert set(only_asn.lookup(PUBLIC_IP)) == {"asn", "org"}
    only_city.close()
    only_asn.close()


@pytest.mark.parametrize(
    "address",
    [
        "203.0.113.5",
        "192.168.1.10",
        "10.0.0.1",
        "127.0.0.1",
        "::1",
        "9.9.9.9",
        "not-an-ip",
        "",
        None,
    ],
)
def test_no_answer_for_private_unknown_or_invalid_addresses(geo, address):
    assert geo.lookup(address) is None


def test_nothing_configured_means_no_geoip():
    assert GeoIP.open(None, None) is None


def test_missing_and_broken_databases_are_reported_by_setting(tmp_path):
    with pytest.raises(ValueError, match="MINISIEM_GEOIP_DB: file not found"):
        GeoIP.open(tmp_path / "missing.mmdb")
    broken = tmp_path / "broken.mmdb"
    broken.write_text("this is not a database", encoding="utf-8")
    with pytest.raises(ValueError, match="MINISIEM_GEOIP_ASN_DB.*not a usable"):
        GeoIP.open(None, broken)


def test_text_from_the_database_is_cut_short(tmp_path):
    record = {"country": {"iso_code": "ZZ", "names": {"en": "Q" * 500}}}
    path = _write(tmp_path / "long.mmdb", "GeoLite2-Country", "8.8.8.0/24", record)
    database = GeoIP.open(path)
    assert len(database.lookup(PUBLIC_IP)["country"]) == 64
    database.close()


def test_registered_country_is_the_fallback(tmp_path):
    record = {"registered_country": {"iso_code": "IE", "names": {"en": "Ireland"}}}
    path = _write(tmp_path / "reg.mmdb", "GeoLite2-Country", "8.8.8.0/24", record)
    database = GeoIP.open(path)
    assert database.lookup(PUBLIC_IP)["country_code"] == "IE"
    database.close()


def test_describe():
    assert describe(None) == ""
    assert describe({"city": "Berlin", "country": "Germany"}) == "Berlin, Germany"
    assert describe({"country_code": "DE"}) == "DE"
    assert describe({"country": "Germany", "asn": 3320, "org": "DTAG"}) == "Germany (AS3320 DTAG)"
    assert describe({"asn": 1}) == "AS1"


# --- in the API -----------------------------------------------------------------------------


def failed_ssh(ip: str, count: int = 5) -> bytes:
    return "\n".join(
        f"Oct 20 09:00:{i:02d} web01 sshd[1]: Failed password for admin from {ip} port 22 ssh2"
        for i in range(count)
    ).encode()


def post(client, ip):
    return client.post(
        "/ingest/auth",
        params={"year": 2026},
        content=failed_ssh(ip),
        headers={"content-type": "text/plain"},
    )


def test_alerts_and_top_sources_carry_the_country(database_url, rules_dir, city_db):
    settings = Settings(
        database_url=database_url,
        rules_dir=rules_dir,
        log_timezone="UTC",
        api_token=None,
        geoip_db=city_db,
    )
    with TestClient(create_app(settings)) as client:
        post(client, PUBLIC_IP)
        post(client, "203.0.113.9")
        alerts = {a["src_ip"]: a for a in client.get("/api/alerts").json()}
        assert alerts[PUBLIC_IP]["geo"]["country_code"] == "US"
        assert alerts["203.0.113.9"]["geo"] is None
        sources = {s["src_ip"]: s for s in client.get("/api/stats").json()["top_sources"]}
        assert sources[PUBLIC_IP]["geo"]["city"] == "Mountain View"


def test_without_a_database_geo_is_null(database_url, rules_dir):
    settings = Settings(
        database_url=database_url, rules_dir=rules_dir, log_timezone="UTC", api_token=None
    )
    with TestClient(create_app(settings)) as client:
        post(client, PUBLIC_IP)
        assert all(a["geo"] is None for a in client.get("/api/alerts").json())


def test_app_refuses_to_start_with_a_missing_database(database_url, rules_dir, tmp_path):
    settings = Settings(
        database_url=database_url,
        rules_dir=rules_dir,
        log_timezone="UTC",
        api_token=None,
        geoip_db=tmp_path / "nope.mmdb",
    )
    with pytest.raises(ValueError, match="file not found"), TestClient(create_app(settings)):
        pass
