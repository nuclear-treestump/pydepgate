"""pydepgate.scannerd.__init__

Scanner daemon for pydepgate.

Intent: This is the main module of the scanner daemon for pydepgate.

How it works: The scanner daemon receives orders from intaked, processes the artifacts with the scan profile requested,
and then saves the result to the pdgdb database. This then makes the data queryable by other components of the system as well.

Workflows:

(intake artifact)
1. intaked receives an artifact and scan profile
2. scannerd processes the artifact with the requested scan profile
3. scannerd saves the result to the pdgdb database
4. scannerd calls auditd to log the action

(rescan artifact)
1. intaked receives an artifact and scan profile
2. scannerd sha512s the artifact
2. scannerd checks if the artifact has already been processed.
If not, all steps are the same as the intake artifact workflow.
If it has, the request is handed off to evidenced to respond to the client.

[future]
(workplan)
1. workplan has a call for pydepgate.scanner.run and a scan profile
2. scannerd processes the artifact with the requested scan profile
3. scannerd saves the result to the pdgdb database
4. scannerd calls auditd to log the action
5. scannerd responds to workplan with an event response payload containing the result, time taken, scan profile, etc.

"""
