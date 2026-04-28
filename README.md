# Mock Security Realm Plugin

An insecure "security realm" designed exclusively for testing and demonstrating other parts of the system, such as authorization strategies.

## Features

- **Simple User Definition**: Define users and groups via a newline-delimited text format (e.g., `username group1 group2 ...`)
- **Username with matching password**: Authentication succeeds when the password equals the username
- **Group Membership**: Supports assigning users to multiple groups
- **Display Names**: Optional display names for users and groups using bracket notation (e.g., `username[Full Name]`, `group1[Group Name]`)
- **Flexible ID Strategies**: Configurable case-sensitive or case-insensitive user and group lookup
- **Simulated Delays**: Optional fixed or random authentication delays for testing performance scenarios
- **Simulated Outages**: Test system resilience with simulated authentication outages
- **Jenkins Configuration as Code**: Full support for JCasC-based configuration

## Changelog

For new changes, see [GitHub releases](https://github.com/jenkinsci/mock-security-realm-plugin/releases).
For older changes, see the [old changelog](https://github.com/jenkinsci/mock-security-realm-plugin/blob/abfb03cb39dfe1a262cbfc73a2bf589830b1fd90/old-changes.md).
