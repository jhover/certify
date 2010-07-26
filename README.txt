Certify--Utilities for managing site host certificates.
======================================================

Uses a plugin architecture to handle cert generation, movement, and submission to a CA for signing. 

OpenSSL-based plugins require pyOpenSSL version 7 or higher, because only these provide access to 
the notBefore and notAfter attributes of certificates (needed to check expiration dates).

We have decided that we will NOT support *copying* a host certificate to other files with different names and/or
owners. Service certs (e.g. 'CN=http/my.host.domain.com') should actually be different certificates.


Prerequisites
=============
-- pexpect
-- pyOpenSSL >= 0.7
-- SSH key login via root must be enabled for any hosts to be managed. 
-- ssh-agent must be running with the correct identity
 