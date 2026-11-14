# Security

phantab lets agents drive pages in a person's own Chrome, with that person's logins, and can fill
saved sign-ins. A flaw here can reach real accounts, so reports are welcome and taken seriously.

## Reporting
Use GitHub's private vulnerability reporting: the repository's **Security** tab, then **Report a
vulnerability**. Do not open a public issue for a security problem.

Include what you did, what happened and what you expected, the release tag or commit you ran,
your OS and Chrome version, and whether a page, an extension or a local process was the attacker.
Leave out real passwords, tokens and vault contents; a fixture value shows the leak just as well.

You can expect an acknowledgement within a week. A confirmed flaw is fixed in the next release, and you
are credited unless you ask not to be.

## Supported versions
Only the latest release gets fixes.

## What counts
The model is `docs/THREAT-MODEL.md`: its attackers, its requirements (SR-1 to SR-77) and its
residual risks (R1 and on). A way around any SR is a vulnerability. A residual risk the model names
is known, and a report that narrows one is still welcome.

In scope, for example:
- a page, a foreign extension or another local user reaching the service, the bridge or the token;
- a saved login reaching a page whose origin it was not saved for, or a value reaching a log, an
  error, a result or a file;
- an agent session acting on another session's page without the owner's confirmation;
- the installer changing client configs, registry keys or files it did not name.

Out of scope: an attacker who already runs code as the same user with the same rights (the model's
residual R1), and a person at the keyboard with the browser unlocked.
