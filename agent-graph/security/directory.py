from state import Confidentiality

# Recipient directory (part of the TCB): the clearance of every address the
# agents may send data to. Addresses are compared case-insensitively.

INTERNAL_DOMAIN = "company.internal"

# Addresses cleared above the default of their domain.
RECIPIENT_CLEARANCE = {
    "accounting@company.internal": Confidentiality.CONFIDENTIAL,
}


def normalize_address(address: str) -> str:
    return str(address).strip().strip("<>").lower()


def recipient_clearance(address: str) -> Confidentiality:
    """
    Clearance of a recipient. Internal mailboxes are INTERNAL unless listed
    in RECIPIENT_CLEARANCE; every other address is external and PUBLIC, since
    the identity of an external party (e.g. the sender of an email) cannot be
    verified.
    """
    address = normalize_address(address)

    if address in RECIPIENT_CLEARANCE:
        return RECIPIENT_CLEARANCE[address]

    if address.endswith("@" + INTERNAL_DOMAIN):
        return Confidentiality.INTERNAL

    return Confidentiality.PUBLIC
