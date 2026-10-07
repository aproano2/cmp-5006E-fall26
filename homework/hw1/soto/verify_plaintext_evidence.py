"""Check plaintext evidence against the local fixture, separately from recovery.

The public target has no plaintext-check API. This reviewer-only verifier reads
literal fixture plaintexts, never private keys. It does not pass the reference
target plaintext to either recovery function. It confirms partial recovery under
the documented known-plaintext assumption, not a ciphertext-only attack.
"""

import ast
from pathlib import Path

from breaks import ctr_log, reused_pad


def fixture_plaintexts(function_name: str, variable_name: str) -> list[bytes]:
    source = Path(reused_pad.target.__file__).read_text()
    tree = ast.parse(source)
    for function in tree.body:
        if isinstance(function, ast.FunctionDef) and function.name == function_name:
            for statement in function.body:
                if isinstance(statement, ast.Assign) and any(
                    isinstance(name, ast.Name) and name.id == variable_name
                    for name in statement.targets
                ):
                    values = ast.literal_eval(statement.value)
                    if isinstance(values, list) and all(
                        isinstance(value, bytes) for value in values
                    ):
                        return values
    raise ValueError(f"literal reference plaintexts unavailable: {function_name}")


def confirm_prefix(recovered: bytes, reference: bytes) -> int:
    if not recovered or len(recovered) > len(reference):
        raise AssertionError("invalid recovery length")
    if recovered != reference[:len(recovered)]:
        raise AssertionError("recovered prefix differs from fixture plaintext")
    return len(reference) - len(recovered)


def require_rejection(recovered: bytes, reference: bytes) -> None:
    try:
        confirm_prefix(recovered, reference)
    except AssertionError:
        return
    raise AssertionError("negative control was incorrectly confirmed")


def verify_case(label, ciphertexts, target_name, recover, reference) -> None:
    recovered = recover(ciphertexts)
    unknown = confirm_prefix(recovered, reference)
    if len(ciphertexts[target_name]) != len(reference) or unknown != 1:
        raise AssertionError("unexpected fixture size or coverage")

    # A wrong recovered byte must fail the independent reference check.
    changed = dict(ciphertexts)
    altered = bytearray(changed[target_name])
    altered[0] ^= 1
    changed[target_name] = bytes(altered)
    require_rejection(recover(changed), reference)

    # The uncovered byte remains unknown even when its ciphertext changes.
    changed = dict(ciphertexts)
    altered = bytearray(changed[target_name])
    altered[-1] ^= 1
    changed[target_name] = bytes(altered)
    changed_prefix = recover(changed)
    if changed_prefix != recovered or confirm_prefix(changed_prefix, reference) != 1:
        raise AssertionError("recovery overclaims coverage of the final byte")

    print(f"{label}: fixture confirms {len(recovered)}/{len(reference)} bytes")
    print("  incorrect prefix rejected; altered final byte remains unknown")


def main() -> None:
    pad_reference = fixture_plaintexts("reused_pad_ciphertexts", "messages")
    for name, crib in reused_pad.KNOWN_PLAINTEXTS.items():
        if crib != pad_reference[int(name.removeprefix("msg"))]:
            raise AssertionError(f"assumed crib differs from fixture: {name}")
    pad_ciphertexts = {
        name: bytes.fromhex(value)
        for name, value in reused_pad.target.reused_pad_ciphertexts().items()
    }
    verify_case(
        "reused_pad", pad_ciphertexts, "msg3",
        lambda values: reused_pad.recover_prefix(values, reused_pad.KNOWN_PLAINTEXTS),
        pad_reference[3],
    )
    inconsistent = dict(reused_pad.KNOWN_PLAINTEXTS)
    crib = bytearray(inconsistent["msg1"])
    crib[0] ^= 1
    inconsistent["msg1"] = bytes(crib)
    try:
        reused_pad.recover_prefix(pad_ciphertexts, inconsistent)
    except ValueError:
        print("  contradictory companion cribs rejected")
    else:
        raise AssertionError("contradictory cribs were accepted")

    log_reference = fixture_plaintexts("ctr_log_entries", "entries")
    if ctr_log.KNOWN_LOG != log_reference[1]:
        raise AssertionError("assumed log1 crib differs from fixture")
    logs = {
        name: bytes.fromhex(value)
        for name, value in ctr_log.target.ctr_log_entries().items()
    }
    verify_case(
        "ctr_log", logs, "log2",
        lambda values: ctr_log.recover_prefix(values, ctr_log.KNOWN_LOG),
        log_reference[2],
    )
    incorrect_crib = bytes([ctr_log.KNOWN_LOG[0] ^ 1]) + ctr_log.KNOWN_LOG[1:]
    require_rejection(ctr_log.recover_prefix(logs, incorrect_crib), log_reference[2])
    print("  incorrect known-log crib rejected by fixture check")
    print("scope: partial known-plaintext recovery; no complete-recovery claim")


if __name__ == "__main__":
    main()
