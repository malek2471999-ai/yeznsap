# Migration to v4.5 E2EE

v4.5 intentionally changes authentication so recovery phrases are no longer sent to the server. Accounts created by older versions used a different server verifier and do not have the new encrypted E2EE identity bundle.

For a clean security boundary, create new v4.5 accounts. Do not silently claim that historical v4.4 messages became end-to-end encrypted retroactively.

If an existing direct chat is present in a reused store and both participants are v4.5-capable, the server can mark the chat as upgraded and requires ciphertext for all new messages. Any older plaintext message records remain explicitly marked `legacy` and were only protected by server at-rest encryption when originally created.
