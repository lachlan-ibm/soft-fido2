

from .none            import build_none_attestation_statement
from .packed          import build_packed_attestation_statement
from .fido_u2f        import build_fido_u2f_attestation_statement
from .tpm             import build_tpm_attestation_statement
from .android         import build_android_safetynet_attestation_statement, build_android_key_attestation_statement
from .apple           import build_apple_attestation_statement

def _error(fmt, *_, **__):
    raise ValueError(f"Unsupported attestation statement format: {fmt}")


_DISPATCH = {
    "none":               build_none_attestation_statement,
    "packed":             build_packed_attestation_statement,
    "packed-self":        build_packed_attestation_statement,
    "fido-u2f":           build_fido_u2f_attestation_statement,
    "tpm":                build_tpm_attestation_statement,
    "android-safetynet":  build_android_safetynet_attestation_statement,
    "android-key":        build_android_key_attestation_statement,
    "apple":              build_apple_attestation_statement,
    "anon":               build_apple_attestation_statement #alias for apple/AnonCA
}


def process_attestation_statement(atteStmtFmt, clientDataHash,
                                  authData, credIdBytes, keyPair, **ctx):
    """Public entry point.  ctx carries the authenticator-level fields
    (hash_alg, salt_len, ca_certificate, ca_key_pair, aaguid,
    cts_profile_match) forwarded from Fido2Authenticator."""
    if atteStmtFmt.startswith("compound"):
        stmts_csv = atteStmtFmt.split(":")
        if len(stmts_csv) != 2:
            raise ValueError(f"Unexpected format: {atteStmtFmt}")
        result = []
        for stmt in stmts_csv[1].split(","):
            fn = _DISPATCH.get(stmt, _error)
            result.append({"fmt": stmt,
                           "attStmt": fn(stmt, clientDataHash,
                                         authData, credIdBytes,
                                         keyPair, **ctx)})
        return result
    fn = _DISPATCH.get(atteStmtFmt, _error)
    return fn(atteStmtFmt, clientDataHash, authData, credIdBytes,
              keyPair, **ctx)