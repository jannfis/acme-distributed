# Changelog

## unreleased

* initial support for handling DNS challenges
* ability to generate private keys if they do not exist yet, for both, ACME accounts and certificates
* added basic ACME account management functionality
* improved logging & error handling
* ability to selectively enable/disable certificates and connectors in configuration

## v0.3.0 - 2018-12-15

* add configurable number of retries for timeout events per endpoint
* introduce connector groups and group mapping
* first steps towards modular connectors framework
* improve SSH connection & error handling
* also test SSH connections in dry run mode

## v0.2.0 - 2018-12-13

* major refactoring of the codebase
* better error handling
* increase verbosity, especially in debug logs

## v0.1.0 - 2018-11-20

* initial release
