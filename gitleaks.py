import enum

from enum import StrEnum

from pydantic import BaseModel

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
    condition: AllowlistCondition
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


class Config(BaseModel):
    rules: list[Rule]
