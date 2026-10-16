"""Policies used by the end-to-end runs and the false-positive study.

``recommended`` follows the profile's own guidance: class patterns only on the
step that originates the data, the lasting effect marked persistent, egress
named by trust domain, a declared label domain. The variants each break one
piece of that guidance, so the study shows what each piece buys.
"""

from __future__ import annotations

from authzen_composition.model import CompositionPolicy, RestrictedSequence, SequenceStep

SENSITIVE = frozenset({"personal_data.*"})
# Every class the PEPs of this deployment assign.
LABEL_DOMAIN = frozenset({"personal_data.*", "public", "document"})


def _exfil(*, classes_on_every_step: bool = False) -> RestrictedSequence:
    later = SENSITIVE if classes_on_every_step else frozenset()
    return RestrictedSequence(
        name="read_personal_write_send_external",
        steps=(
            SequenceStep("read_record", result_classes=SENSITIVE),
            SequenceStep("write_document", result_classes=later),
            SequenceStep("send_message", resources=frozenset({"external:*"})),
        ),
        requestable=True,
    )


def _share(*, persistent: bool = True, classes_on_every_step: bool = False) -> RestrictedSequence:
    later = SENSITIVE if classes_on_every_step else frozenset()
    return RestrictedSequence(
        name="read_personal_write_share_public",
        steps=(
            SequenceStep("read_record", result_classes=SENSITIVE),
            SequenceStep("write_document", result_classes=later),
            SequenceStep("share_document", persistent=persistent),
        ),
        # Requestable, like the send: a public FAQ shared after a salary
        # review is legitimate, and a person should be able to approve it.
        requestable=True,
    )


POLICIES: dict[str, CompositionPolicy] = {
    "recommended": CompositionPolicy((_exfil(), _share()), label_domain=LABEL_DOMAIN),
    "no_persistent_mark": CompositionPolicy(
        (_exfil(), _share(persistent=False)), label_domain=LABEL_DOMAIN),
    "classes_on_every_step": CompositionPolicy(
        (_exfil(classes_on_every_step=True), _share(classes_on_every_step=True)),
        label_domain=LABEL_DOMAIN),
    "no_label_domain": CompositionPolicy((_exfil(), _share())),
    # A second PDP replica that, mid-rollout, only knows the exfil sequence.
    "replica_old": CompositionPolicy((_exfil(),), label_domain=LABEL_DOMAIN),
    # No Restricted Sequences: used only to check that the oracle bites.
    "none": CompositionPolicy(()),
}
