"""pydepgate.daemons.evidenced.__init__

pydepgate evidenced daemon module.

Intent: This will be pydepgate's evidence daemon for managing and storing evidence.

Expectation: This daemon will be responsible for accepting incoming scan results from other pydepgate instances in use org-wide,
authenticate with mTLS, and process the scan results for storage into the pdgdb database.

mTLS permits authentication in stdlib while being more secure by not using a shared secret. This can make deploymment more complex
and there are some edge cases (e.g., certificate validation, key management, key rotation) that I haven't fully mapped yet.

This can also hook auditd to emit audit events for each scan result.

evidenced may also provide an API for querying and retrieving stored evidence. Implementation details are pending.

"""
