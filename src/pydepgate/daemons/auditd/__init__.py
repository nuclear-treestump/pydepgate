"""pydepgate.daemons.auditd.__init__

Pydepgate auditd daemon module.

Intent: This will be pydepgate's audit daemon for EXTERNAL log production. This is NOT for internal logging.

This will produce a StructuredLogJSON object for each audit event, sinking it into what the client has configured.

Sinks that will be supported include:
- File-based logging
- Network-based logging (e.g., syslog, HTTP)
- Database logging
- SIEM logging (e.g., Splunk, ELK)

This will utilize a new configuration type, Sinkmaps, which convert pydepgate internal fields to what the client expects.

This means that you can adapt pydepgate's internal logging to match the client's expected format without modifying the core logging logic.

This is subject to change until the daemon actually exists.

"""
