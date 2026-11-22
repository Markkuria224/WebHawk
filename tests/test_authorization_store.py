import json
from datetime import datetime, timezone

import pytest

from webhawk.core.authorization import AuthorizationProfile
from webhawk.core.authorization_store import (
    AuthorizationProfileConflictError,
    AuthorizationStore,
    AuthorizationStoreCorruptionError,
    AuthorizationStoreError,
)


def make_profile(name="Local Lab", hosts=("lab.local",)):
    return AuthorizationProfile(
        name=name,
        authorized_hosts=hosts,
        authorized_networks=("192.168.1.0/24",),
    )


def test_missing_store_returns_empty_profiles(tmp_path):
    store = AuthorizationStore(tmp_path / "profiles.json")

    assert store.list_profiles() == ()


def test_profile_survives_save_and_reload(tmp_path):
    path = tmp_path / "profiles.json"

    store = AuthorizationStore(path)
    store.save_profile(make_profile())

    reloaded = AuthorizationStore(path)

    profiles = reloaded.list_profiles()

    assert len(profiles) == 1
    assert profiles[0].name == "Local Lab"
    assert profiles[0].authorized_hosts == ("lab.local",)
    assert profiles[0].authorized_networks == ("192.168.1.0/24",)


def test_store_creates_parent_directories(tmp_path):
    path = tmp_path / "nested" / "data" / "profiles.json"
    store = AuthorizationStore(path)

    store.save_profile(make_profile())

    assert path.is_file()


def test_profiles_are_sorted_by_name(tmp_path):
    store = AuthorizationStore(tmp_path / "profiles.json")

    store.save_profile(make_profile("Zulu"))
    store.save_profile(make_profile("Alpha"))
    store.save_profile(make_profile("Middle"))

    assert [p.name for p in store.list_profiles()] == [
        "Alpha",
        "Middle",
        "Zulu",
    ]


def test_profile_lookup_is_case_insensitive(tmp_path):
    store = AuthorizationStore(tmp_path / "profiles.json")
    store.save_profile(make_profile("Local Lab"))

    assert store.get_profile("local lab").name == "Local Lab"


def test_missing_profile_lookup_returns_none(tmp_path):
    store = AuthorizationStore(tmp_path / "profiles.json")

    assert store.get_profile("Missing") is None


def test_update_preserves_creation_timestamp(tmp_path):
    store = AuthorizationStore(tmp_path / "profiles.json")

    original = store.save_profile(make_profile())

    updated_input = make_profile(
        hosts=("new.lab.local",)
    )

    updated = store.save_profile(updated_input)

    assert updated.created_at == original.created_at
    assert updated.updated_at >= original.updated_at
    assert updated.authorized_hosts == ("new.lab.local",)
    assert len(store.list_profiles()) == 1


def test_duplicate_profile_names_are_updated_not_duplicated(tmp_path):
    store = AuthorizationStore(tmp_path / "profiles.json")

    store.save_profile(make_profile("Local Lab"))
    store.save_profile(make_profile("LOCAL LAB"))

    assert len(store.list_profiles()) == 1


def test_delete_profile_removes_existing_profile(tmp_path):
    store = AuthorizationStore(tmp_path / "profiles.json")
    store.save_profile(make_profile())

    assert store.delete_profile("LOCAL LAB") is True
    assert store.list_profiles() == ()


def test_delete_missing_profile_returns_false(tmp_path):
    store = AuthorizationStore(tmp_path / "profiles.json")

    assert store.delete_profile("Missing") is False


def test_storage_contains_schema_version(tmp_path):
    path = tmp_path / "profiles.json"
    store = AuthorizationStore(path)

    store.save_profile(make_profile())

    data = json.loads(path.read_text(encoding="utf-8"))

    assert data["schema_version"] == 1
    assert len(data["profiles"]) == 1


def test_corrupted_json_is_rejected(tmp_path):
    path = tmp_path / "profiles.json"
    path.write_text("{invalid json", encoding="utf-8")

    store = AuthorizationStore(path)

    with pytest.raises(AuthorizationStoreCorruptionError):
        store.list_profiles()


def test_unsupported_schema_version_is_rejected(tmp_path):
    path = tmp_path / "profiles.json"
    path.write_text(
        json.dumps({
            "schema_version": 999,
            "profiles": [],
        }),
        encoding="utf-8",
    )

    store = AuthorizationStore(path)

    with pytest.raises(AuthorizationStoreCorruptionError):
        store.list_profiles()


def test_invalid_stored_profile_is_rejected(tmp_path):
    path = tmp_path / "profiles.json"
    path.write_text(
        json.dumps({
            "schema_version": 1,
            "profiles": [
                {
                    "name": "Invalid",
                    "authorized_hosts": ["*.example.com"],
                    "authorized_networks": [],
                    "allow_loopback": False,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }
            ],
        }),
        encoding="utf-8",
    )

    store = AuthorizationStore(path)

    with pytest.raises(AuthorizationStoreCorruptionError):
        store.list_profiles()


def test_duplicate_stored_profile_names_are_rejected(tmp_path):
    path = tmp_path / "profiles.json"
    profile = make_profile().model_dump(mode="json")

    path.write_text(
        json.dumps({
            "schema_version": 1,
            "profiles": [
                profile,
                {**profile, "name": "LOCAL LAB"},
            ],
        }),
        encoding="utf-8",
    )

    store = AuthorizationStore(path)

    with pytest.raises(AuthorizationStoreCorruptionError):
        store.list_profiles()


def test_interrupted_atomic_write_preserves_existing_file(
    tmp_path,
    monkeypatch,
):
    path = tmp_path / "profiles.json"
    store = AuthorizationStore(path)

    store.save_profile(make_profile())

    original_content = path.read_bytes()

    def fail_replace(source, destination):
        raise OSError("Simulated interrupted replacement.")

    monkeypatch.setattr(
        "webhawk.core.authorization_store.os.replace",
        fail_replace,
    )

    with pytest.raises(AuthorizationStoreError):
        store.save_profile(make_profile("Second Profile"))

    assert path.read_bytes() == original_content
    assert len(AuthorizationStore(path).list_profiles()) == 1

    temporary_files = list(
        tmp_path.glob(".profiles.json.*.tmp")
    )

    assert temporary_files == []

def test_boolean_schema_version_is_rejected(tmp_path):
    path = tmp_path / "profiles.json"
    path.write_text(
        json.dumps({
            "schema_version": True,
            "profiles": [],
        }),
        encoding="utf-8",
    )

    store = AuthorizationStore(path)

    with pytest.raises(AuthorizationStoreCorruptionError):
        store.list_profiles()


def test_string_boolean_in_stored_profile_is_rejected(tmp_path):
    path = tmp_path / "profiles.json"
    profile = make_profile().model_dump(mode="json")
    profile["allow_loopback"] = "yes"

    path.write_text(
        json.dumps({
            "schema_version": 1,
            "profiles": [profile],
        }),
        encoding="utf-8",
    )

    store = AuthorizationStore(path)

    with pytest.raises(AuthorizationStoreCorruptionError):
        store.list_profiles()


def test_directory_creation_error_is_wrapped(
    tmp_path,
    monkeypatch,
):
    path = tmp_path / "blocked" / "profiles.json"
    store = AuthorizationStore(path)

    def fail_mkdir(*args, **kwargs):
        raise OSError("Simulated directory creation failure.")

    monkeypatch.setattr(
        "pathlib.Path.mkdir",
        fail_mkdir,
    )

    with pytest.raises(AuthorizationStoreError):
        store.save_profile(make_profile())


def test_profile_update_uses_valid_timestamps(tmp_path):
    store = AuthorizationStore(tmp_path / "profiles.json")

    original = store.save_profile(make_profile())
    updated = store.save_profile(
        make_profile(hosts=("updated.lab.local",))
    )

    assert updated.created_at == original.created_at
    assert updated.updated_at.tzinfo is not None
    assert updated.updated_at >= updated.created_at

def test_rename_profile_preserves_creation_timestamp(tmp_path):
    store = AuthorizationStore(tmp_path / "profiles.json")

    original = store.save_profile(make_profile("Local Lab"))

    updated = AuthorizationProfile(
        name="Production Lab",
        authorized_hosts=("production.example.com",),
        authorized_networks=("192.168.1.0/24",),
    )

    renamed = store.rename_profile("Local Lab", updated)

    assert renamed.name == "Production Lab"
    assert renamed.created_at == original.created_at
    assert renamed.updated_at >= original.updated_at
    assert renamed.authorized_hosts == ("production.example.com",)
    assert store.get_profile("Local Lab") is None
    assert store.get_profile("Production Lab") == renamed
    assert len(store.list_profiles()) == 1


def test_rename_profile_rejects_case_insensitive_duplicate(tmp_path):
    store = AuthorizationStore(tmp_path / "profiles.json")

    store.save_profile(make_profile("Local Lab"))
    store.save_profile(make_profile("Production Lab"))

    updated = AuthorizationProfile(
        name="PRODUCTION LAB",
        authorized_hosts=("new.example.com",),
        authorized_networks=("192.168.1.0/24",),
    )

    with pytest.raises(AuthorizationProfileConflictError):
        store.rename_profile("Local Lab", updated)

    assert store.get_profile("Local Lab") is not None
    assert store.get_profile("Production Lab") is not None
    assert len(store.list_profiles()) == 2


def test_rename_profile_allows_keeping_same_name(tmp_path):
    store = AuthorizationStore(tmp_path / "profiles.json")

    original = store.save_profile(make_profile("Local Lab"))

    updated = make_profile(
        "Local Lab",
        hosts=("updated.example.com",),
    )

    renamed = store.rename_profile("Local Lab", updated)

    assert renamed.name == "Local Lab"
    assert renamed.created_at == original.created_at
    assert renamed.authorized_hosts == ("updated.example.com",)
    assert len(store.list_profiles()) == 1


def test_rename_profile_missing_original_is_rejected(tmp_path):
    store = AuthorizationStore(tmp_path / "profiles.json")

    with pytest.raises(AuthorizationStoreError):
        store.rename_profile(
            "Missing Profile",
            make_profile("Renamed Profile"),
        )

    assert store.list_profiles() == ()


def test_rename_profile_preserves_original_on_atomic_write_failure(
    tmp_path,
    monkeypatch,
):
    path = tmp_path / "profiles.json"
    store = AuthorizationStore(path)

    original = store.save_profile(make_profile("Local Lab"))
    original_content = path.read_bytes()

    updated = make_profile("Renamed Lab")

    def fail_replace(source, destination):
        raise OSError("Simulated interrupted replacement.")

    monkeypatch.setattr(
        "webhawk.core.authorization_store.os.replace",
        fail_replace,
    )

    with pytest.raises(AuthorizationStoreError):
        store.rename_profile("Local Lab", updated)

    assert path.read_bytes() == original_content
    assert store.get_profile("Local Lab") == original
    assert store.get_profile("Renamed Lab") is None



@pytest.mark.parametrize(
    "stored_data",
    [
        [],
        {"schema_version": 1},
        {
            "schema_version": 1,
            "profiles": [],
            "unexpected": True,
        },
        {
            "schema_version": 1,
            "profiles": {},
        },
    ],
)
def test_invalid_storage_structure_is_rejected(tmp_path, stored_data):
    path = tmp_path / "profiles.json"
    path.write_text(json.dumps(stored_data), encoding="utf-8")

    store = AuthorizationStore(path)

    with pytest.raises(AuthorizationStoreCorruptionError):
        store.list_profiles()


def test_get_profile_rejects_non_string_name(tmp_path):
    store = AuthorizationStore(tmp_path / "profiles.json")

    with pytest.raises(TypeError, match="Profile name must be a string"):
        store.get_profile(None)


def test_save_profile_rejects_invalid_object(tmp_path):
    store = AuthorizationStore(tmp_path / "profiles.json")

    with pytest.raises(TypeError, match="Expected an AuthorizationProfile"):
        store.save_profile(object())


def test_rename_profile_rejects_non_string_original_name(tmp_path):
    store = AuthorizationStore(tmp_path / "profiles.json")

    with pytest.raises(TypeError, match="Original profile name must be a string"):
        store.rename_profile(None, make_profile())


def test_rename_profile_rejects_invalid_updated_profile(tmp_path):
    store = AuthorizationStore(tmp_path / "profiles.json")

    with pytest.raises(TypeError, match="Expected an AuthorizationProfile"):
        store.rename_profile("Local Lab", object())


def test_delete_profile_rejects_non_string_name(tmp_path):
    store = AuthorizationStore(tmp_path / "profiles.json")

    with pytest.raises(TypeError, match="Profile name must be a string"):
        store.delete_profile(None)


def test_storage_read_os_error_is_wrapped(tmp_path, monkeypatch):
    path = tmp_path / "profiles.json"
    path.write_text("{}", encoding="utf-8")

    store = AuthorizationStore(path)
    original_open = type(path).open

    def fail_open(self, *args, **kwargs):
        if self == path:
            raise OSError("Simulated read failure.")
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(type(path), "open", fail_open)

    with pytest.raises(AuthorizationStoreCorruptionError):
        store.list_profiles()


def test_fsync_failure_preserves_existing_file_and_cleans_temporary_file(
    tmp_path,
    monkeypatch,
):
    path = tmp_path / "profiles.json"
    store = AuthorizationStore(path)

    store.save_profile(make_profile())
    original_content = path.read_bytes()

    def fail_fsync(file_descriptor):
        raise OSError("Simulated fsync failure.")

    monkeypatch.setattr(
        "webhawk.core.authorization_store.os.fsync",
        fail_fsync,
    )

    with pytest.raises(AuthorizationStoreError):
        store.save_profile(make_profile("Second Profile"))

    assert path.read_bytes() == original_content

    temporary_files = list(
        tmp_path.glob(".profiles.json.*.tmp")
    )

    assert temporary_files == []
