"""Reference implementation of the AuthZEN Mission Composition Profile.

This package implements, over the OpenID AuthZEN Authorization API 1.0:

* a composition predicate that is unsatisfied when admitting a request would
  complete a restricted ordered sequence of acts in a mission;
* result classes, a label assigned by the enforcing side describing what an
  executed act returned;
* a mission-wide admission order, provided by a Mission History Service, that
  the predicate needs when the acts of one mission are enforced at more than
  one PEP.

See docs/authzen-composition-profile-1_0.md for the profile.
"""

from authzen_composition.model import (
    Act,
    ActOutcome,
    CompositionPolicy,
    RestrictedSequence,
    SequenceStep,
)
from authzen_composition.types import (
    Decision,
    EvaluationRequest,
    EvaluationResponse,
    Obligation,
)

__all__ = [
    "Act",
    "ActOutcome",
    "CompositionPolicy",
    "Decision",
    "EvaluationRequest",
    "EvaluationResponse",
    "Obligation",
    "RestrictedSequence",
    "SequenceStep",
]

__version__ = "0.2.0"
