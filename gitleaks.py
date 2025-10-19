import enum
import tomllib

from enum import StrEnum
from typing import BinaryIO

from pydantic import BaseModel
from pydantic import model_validator

from sssig import OptionalPositiveInt
from sssig import OptionalPositiveFloat
from sssig import Pattern


class RegexTarget(StrEnum):
    LINE = enum.auto()
    MATCH = enum.auto()
    SECRET = enum.auto()


class AllowlistCondition(StrEnum):
    AND = enum.auto()
    OR = enum.auto()


class Allowlist(BaseModel):
    condition: AllowlistCondition | None = None
    regexTarget: RegexTarget | None = None
    paths: list[Pattern] | None = None
    regexes: list[Pattern] | None = None
    stopwords: list[str] | None = None


class Required(BaseModel):
    id: str
    withinLines: OptionalPositiveInt = None
    withinColumns: OptionalPositiveInt = None


class Rule(BaseModel):
    id: str
    description: str | None = None
    path: Pattern | None = None
    regex: Pattern | None = None
    entropy: OptionalPositiveFloat = None
    keywords: list[str] | None = None
    tags: list[str] | None = None
    skipReport: bool | None = None
    allowlists: list[Allowlist] | None = None
    required: list[Required] | None = None

    @model_validator(mode='before')
    @classmethod
    def convert_allowlist_to_allowlists(cls, data):
        """Convert single allowlist to allowlists list."""
        if isinstance(data, dict) and 'allowlist' in data:
            # Convert single allowlist to list of allowlists
            data['allowlists'] = [data.pop('allowlist')]
        return data


class Config(BaseModel):
    rules: list[Rule]


def load(fp: BinaryIO) -> Config:
    """Load a Gitleaks config from a TOML file."""
    data = tomllib.load(fp)
    return Config.model_validate(data)
