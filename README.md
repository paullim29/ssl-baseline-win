ssl-baseline-win
===================

This Compliance Profile demonstrates the use of InSpec's [SSL resource](https://www.inspec.io/docs/reference/resources/ssl/) by enforcing strong TLS configuration.

The tests are based on
- [Mozillas TLS Guidelines](https://wiki.mozilla.org/Security/Server_Side_TLS)
- [OWASP TLS Cheat Sheet](https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet)
- [Cipherli.st](https://cipherli.st/)

## Standalone Usage

Requires [InSpec](https://github.com/chef/inspec) 1.21.0 or newer for execution:

```
$ git clone https://github.com/dev-sec/ssl-baseline
$ inspec exec ssl-baseline-win
