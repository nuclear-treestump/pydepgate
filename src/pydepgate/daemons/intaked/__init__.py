"""pydepgate.daemons.intaked.__init__

pydepgate intaked daemon module.

Intent: This will be pydepgate's intake daemon for initiating a scan or other operation based on incoming data.

Expectation: This daemon will be responsible for receiving incoming data, validating it, and triggering the appropriate scan or operation.

This daemon's primary purpose is to kick off scans / other operations based on the received data. The expected workflow is to either:

1. respond to (future) Workplan requests (pydepgate automation!)
2. receive a scan request from another pydepgate instance
3. receive a manual scan request from a user or system not on the same machine as the running pydepgate daemon
4. run a scheduled scan or operation

This daemon may also provide an API for querying and retrieving the status of ongoing scans or operations. Implementation details are pending.

The major benefit here is reduction of repeated scans by calling evidenced to pull the matching SHA512 hash for an existing artifact. This reduces
total scan time and could reduce CI minutes.

"""
