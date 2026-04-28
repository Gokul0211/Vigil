from models.intent import IntentMessage

# Domains that make a call security-relevant
SECURITY_RELEVANT_DOMAINS = {
    "auth", "crypto", "logging", "data-exposure",
    "input-validation", "file-system", "network"
}

# Keyword sets for diff-based inference — used when agent passes empty/garbage affects
SENSITIVE_KEYWORDS: dict[str, list[str]] = {
    "auth": [
        "jwt", "token", "session", "login", "logout", "password", "bearer",
        "authenticate", "authorize", "oauth", "api_key", "apikey", "secret_key"
    ],
    "crypto": [
        "encrypt", "decrypt", "hash", "hmac", "aes", "rsa", "sha256",
        "pbkdf2", "bcrypt", "scrypt", "argon2", "cipher", "iv", "nonce"
    ],
    "logging": [
        "console.log", "logger.", "log.info", "log.debug", "log.error",
        "log.warn", "print(", "logging.", "winston", "pino", "bunyan",
        "structlog", "sentry"
    ],
    "data-exposure": [
        "pii", "email", "card", "ssn", "address", "phone", "dob",
        "date_of_birth", "credit_card", "cvv", "account_number",
        "social_security", "passport", "license"
    ],
    "input-validation": [
        "request.body", "req.body", "req.query", "req.params",
        "user_input", "form.get", "request.form", "request.args",
        "request.json", "request.data", "getattr(request",
        "flask.request", "fastapi.request"
    ],
    "file-system": [
        "open(", "os.path", "pathlib", "shutil", "os.remove",
        "os.rename", "os.makedirs", "file.write", "file.read",
        "subprocess", "exec(", "eval("
    ],
    "network": [
        "requests.get", "requests.post", "httpx.", "aiohttp.",
        "fetch(", "axios.", "urllib", "socket.", "http.client",
        "grpc.", "websocket"
    ],
}

# High-confidence dangerous patterns — these alone make a call security-relevant
# regardless of what `affects` says
ALWAYS_RELEVANT_PATTERNS = [
    "eval(",
    "exec(",
    "os.system(",
    "subprocess.call(",
    "subprocess.run(",
    "__import__(",
    "pickle.loads(",
    "yaml.load(",       # yaml.safe_load is fine, yaml.load is not
    "deserialize(",
    "marshal.loads(",
]


def is_security_relevant(intent: IntentMessage, diff: str) -> bool:
    """
    Returns True if this tool call should be routed to Tier 1.
    Returns False if it can be skipped entirely.

    A call is security-relevant if ANY of these are true:
    - intent.affects contains at least one known security domain
    - intent.invariants_touched is non-empty
    - intent.assumes is non-empty (unverified assumptions are always worth checking)
    - diff contains an always-relevant pattern (eval, exec, etc.)
    - diff-based keyword inference returns non-empty results
    """
    # Explicit affects from agent
    if any(d in SECURITY_RELEVANT_DOMAINS for d in intent.affects):
        return True

    # Agent flagged invariants or assumptions
    if intent.invariants_touched:
        return True
    if intent.assumes:
        return True

    # Always-relevant patterns in diff — checked case-insensitively
    diff_lower = diff.lower()
    if any(p in diff_lower for p in ALWAYS_RELEVANT_PATTERNS):
        return True

    # Keyword-based inference — if anything beyond "unknown" was found, route it
    inferred = infer_affects_from_diff(diff)
    if inferred and inferred != ["unknown"]:
        return True

    return False


def infer_affects_from_diff(diff: str) -> list[str]:
    """
    Infers security-relevant domains from the diff text.
    Used when the agent passes empty or garbage `affects`.

    Returns a list of domain strings, or ["unknown"] if nothing matched.
    "unknown" is not safe to skip — it still routes to Tier 1.
    """
    found = []
    diff_lower = diff.lower()
    for domain, keywords in SENSITIVE_KEYWORDS.items():
        if any(kw in diff_lower for kw in keywords):
            found.append(domain)
    return found if found else ["unknown"]


def classify(intent: IntentMessage, diff: str) -> tuple[bool, list[str], bool]:
    """
    Main entry point for the classifier.

    Returns:
        (should_route_to_tier1: bool, effective_affects: list[str], used_inference: bool)

    `used_inference` is True when the agent's `affects` was empty/malformed and
    we fell back to diff-based inference. This is logged as a malformed intent signal.
    """
    used_inference = False
    effective_affects = list(intent.affects)

    # Check if intent is empty or malformed — fall back to diff inference
    if intent.is_empty or intent.is_malformed or not intent.affects:
        inferred = infer_affects_from_diff(diff)
        effective_affects = inferred
        used_inference = True

    # Build a temporary intent with effective_affects for the relevance check
    # (we do not mutate the original intent object)
    check_intent = intent.model_copy(update={"affects": effective_affects})
    relevant = is_security_relevant(check_intent, diff)

    return relevant, effective_affects, used_inference
