import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from pydantic import ValidationError

from webhawk.core.authorization import AuthorizationProfile


SCHEMA_VERSION = 1


class AuthorizationStoreError(RuntimeError):
    """Base exception for authorization storage failures."""


class AuthorizationStoreCorruptionError(AuthorizationStoreError):
    """Raised when stored authorization data is invalid or corrupted."""


class AuthorizationProfileConflictError(AuthorizationStoreError):
    """Raised when a profile rename conflicts with another profile."""


def get_default_store_path() -> Path:
    """Return the platform-appropriate WebHawk authorization data path."""

    if os.name == "nt":
        base = Path(
            os.environ.get(
                "LOCALAPPDATA",
                str(Path.home() / "AppData" / "Local"),
            )
        )
    elif os.name == "posix" and os.uname().sysname == "Darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(
            os.environ.get(
                "XDG_DATA_HOME",
                str(Path.home() / ".local" / "share"),
            )
        )

    return base / "WebHawk" / "authorization_profiles.json"


class AuthorizationStore:
    """Persistent, versioned storage for authorization profiles."""

    def __init__(self, path: Path | str | None = None):
        self.path = Path(path) if path is not None else get_default_store_path()

    def _read_profiles(self) -> list[AuthorizationProfile]:
        try:
            if not self.path.exists():
                return []

            with self.path.open("r", encoding="utf-8") as file:
                data = json.load(file)

            if not isinstance(data, dict):
                raise ValueError("Storage root must be an object.")

            if set(data) != {"schema_version", "profiles"}:
                raise ValueError("Storage structure is unsupported.")

            version = data["schema_version"]

            if type(version) is not int or version != SCHEMA_VERSION:
                raise ValueError("Unsupported authorization storage version.")

            if not isinstance(data["profiles"], list):
                raise ValueError("Profiles must be stored as a list.")

            profiles = [
                AuthorizationProfile.model_validate(item)
                for item in data["profiles"]
            ]

            names = [profile.name.casefold() for profile in profiles]

            if len(names) != len(set(names)):
                raise ValueError("Duplicate profile names were found.")

            return profiles

        except (
            OSError,
            json.JSONDecodeError,
            ValueError,
            TypeError,
            ValidationError,
        ) as exc:
            raise AuthorizationStoreCorruptionError(
                "Authorization profiles could not be loaded safely."
            ) from exc

    def _write_profiles(
        self,
        profiles: list[AuthorizationProfile],
    ) -> None:
        temporary_path = None

        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)

            payload = {
                "schema_version": SCHEMA_VERSION,
                "profiles": [
                    profile.model_dump(mode="json")
                    for profile in profiles
                ],
            }

            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                newline="\n",
                dir=self.path.parent,
                prefix=f".{self.path.name}.",
                suffix=".tmp",
                delete=False,
            ) as file:
                temporary_path = Path(file.name)

                json.dump(
                    payload,
                    file,
                    indent=2,
                    ensure_ascii=True,
                )

                file.write("\n")
                file.flush()
                os.fsync(file.fileno())

            os.replace(temporary_path, self.path)

        except OSError as exc:
            raise AuthorizationStoreError(
                "Authorization profiles could not be saved."
            ) from exc

        finally:
            if temporary_path is not None:
                try:
                    temporary_path.unlink(missing_ok=True)
                except OSError:
                    pass

    def list_profiles(self) -> tuple[AuthorizationProfile, ...]:
        """Return all stored profiles."""

        return tuple(self._read_profiles())

    def get_profile(self, name: str) -> AuthorizationProfile | None:
        """Find a profile using a case-insensitive name."""

        if not isinstance(name, str):
            raise TypeError("Profile name must be a string.")

        normalized_name = name.strip().casefold()

        return next(
            (
                profile
                for profile in self._read_profiles()
                if profile.name.casefold() == normalized_name
            ),
            None,
        )

    def save_profile(
        self,
        profile: AuthorizationProfile,
    ) -> AuthorizationProfile:
        """Create or update a profile without changing its creation time."""

        if not isinstance(profile, AuthorizationProfile):
            raise TypeError("Expected an AuthorizationProfile.")

        profiles = self._read_profiles()

        existing = next(
            (
                item
                for item in profiles
                if item.name.casefold() == profile.name.casefold()
            ),
            None,
        )

        if existing is not None:
            profile_data = profile.model_dump()

            profile_data["created_at"] = existing.created_at
            profile_data["updated_at"] = max(
                datetime.now(timezone.utc),
                existing.updated_at,
            )

            profile = AuthorizationProfile.model_validate(profile_data)

            profiles = [
                item
                for item in profiles
                if item.name.casefold() != profile.name.casefold()
            ]

        profiles.append(profile)
        profiles.sort(key=lambda item: item.name.casefold())

        self._write_profiles(profiles)

        return profile

    def rename_profile(
        self,
        old_name: str,
        updated_profile: AuthorizationProfile,
    ) -> AuthorizationProfile:
        """Rename and update a profile without losing its original identity."""

        if not isinstance(old_name, str):
            raise TypeError("Original profile name must be a string.")

        if not isinstance(updated_profile, AuthorizationProfile):
            raise TypeError("Expected an AuthorizationProfile.")

        normalized_old_name = old_name.strip().casefold()
        profiles = self._read_profiles()

        original_index = next(
            (
                index
                for index, item in enumerate(profiles)
                if item.name.casefold() == normalized_old_name
            ),
            None,
        )

        if original_index is None:
            raise AuthorizationStoreError(
                "The original authorization profile no longer exists."
            )

        original = profiles[original_index]
        normalized_new_name = updated_profile.name.casefold()

        conflict = any(
            index != original_index
            and item.name.casefold() == normalized_new_name
            for index, item in enumerate(profiles)
        )

        if conflict:
            raise AuthorizationProfileConflictError(
                "Another authorization profile already uses that name."
            )

        profile_data = updated_profile.model_dump()
        profile_data["created_at"] = original.created_at
        profile_data["updated_at"] = max(
            datetime.now(timezone.utc),
            original.updated_at,
        )

        renamed_profile = AuthorizationProfile.model_validate(profile_data)

        profiles[original_index] = renamed_profile
        profiles.sort(key=lambda item: item.name.casefold())

        self._write_profiles(profiles)

        return renamed_profile

    def delete_profile(self, name: str) -> bool:
        """Delete a profile by name. Return False if it does not exist."""

        if not isinstance(name, str):
            raise TypeError("Profile name must be a string.")

        normalized_name = name.strip().casefold()
        profiles = self._read_profiles()

        remaining = [
            profile
            for profile in profiles
            if profile.name.casefold() != normalized_name
        ]

        if len(remaining) == len(profiles):
            return False

        self._write_profiles(remaining)
        return True
