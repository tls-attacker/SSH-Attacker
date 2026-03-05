# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SSH-Attacker is a Java-based framework for analyzing SSH protocol implementations. It sends arbitrary protocol messages in arbitrary order to SSH peers, supporting runtime modifications via modifiable variables. It is a research/pentesting tool, not an end-user application.

## Build Commands

Requires **Java JDK 21** and **Maven**.

```bash
# Full build
mvn clean install

# Build without tests
mvn clean install -DskipTests=true

# Run unit tests only (excludes IntegrationTest and SlowTest)
mvn test

# Run unit + integration + slow tests
mvn verify

# Run a single test class
mvn test -pl SSH-Core -Dtest=ClassName

# Run a single test method
mvn test -pl SSH-Core -Dtest=ClassName#methodName

# Check formatting
mvn spotless:check

# Auto-fix formatting
mvn spotless:apply

# Build with coverage
mvn -Pcoverage verify
```

Built JARs are placed in the `apps/` folder.

## Code Formatting

Uses **Spotless** with Google Java Format (AOSP style, 4-space indent). CI enforces `mvn spotless:check`. Run `mvn spotless:apply` before committing. All Java files require the Apache 2.0 license header from `license_header_plain.txt`.

## Module Structure

Multi-module Maven project (`de.rub.nds.ssh.attacker`), parent BOM: `protocol-toolkit-bom:5.0.0`.

- **SSH-Core** (`ssh-core`): The protocol stack and heart of the framework. All other modules depend on this.
- **SSH-Client** (`ssh-client`): Demo client application. Entry: `SshClient.java`.
- **SSH-Server** (`ssh-server`): Demo server application. Entry: `SshServer.java`.
- **SSH-Mitm** (`ssh-mitm`): Man-in-the-middle proxy with independent key exchanges. Entry: `Main.java`.
- **Attacks** (`attacks`): Example attack implementations (padding oracle, PKCS#1, etc.).

## Architecture

### Protocol Layers

The core follows the SSH RFC layered architecture, each in its own package under `core.protocol`:

- **`transport`** (RFC 4253): Version exchange, key exchange, encryption negotiation, extensions
- **`authentication`** (RFC 4252): User auth methods (password, publickey, keyboard-interactive, hostbased, none)
- **`connection`** (RFC 4254): Channels (session, direct-tcpip, forwarded-tcpip, x11), channel requests, global requests
- **SFTP**: File transfer protocol layer (under `data.sftp`)

### Message Quartet Pattern

Every SSH message type follows a consistent four-class pattern:

1. **Message** (`*Message.java`): Data holder with `ModifiableVariable` fields and JAXB annotations
2. **Parser** (`*MessageParser.java`): Deserializes bytes into the message object
3. **Preparator** (`*MessagePreparator.java`): Sets field values from `Config`/`SshContext` before sending. Preparator methods should be `protected` visibility.
4. **Serializer** (`*MessageSerializer.java`): Serializes the message to bytes
5. **Handler** (`*MessageHandler.java`): Processes received messages and updates `SshContext`

Base classes: `SshMessage` → `SshMessageParser`, `SshMessagePreparator`, `SshMessageSerializer`, `SshMessageHandler`.

### Workflow Engine

- **`WorkflowTrace`**: Ordered list of actions defining a protocol flow (Java API or XML/JAXB)
- **Actions**: `SendAction`, `ReceiveAction`, `ChangePacketLayerAction`, `DynamicKeyExchangeAction`, `ActivateEncryptionAction`, etc.
- **`State`**: Holds `Config` + `WorkflowTrace` + connections
- **`SshContext`**: Runtime state tracking negotiated algorithms, keys, channels, sequence numbers
- **`DefaultWorkflowExecutor`**: Executes actions in sequence

### Key Concepts

- **ModifiableVariables**: Fields use types like `ModifiableByte`, `ModifiableInteger`, `ModifiableByteArray` from the `modifiable-variable` library to allow runtime value tweaking without changing the workflow definition.
- **Config**: Central configuration object (`Config.java`) with JAXB XML binding. Hardcoded defaults are used when config values are not explicitly set.
- **Packet Layer**: Binary packet handling (encryption, MAC, compression) lives in `core.packet`.

### Key Dependencies

- `de.rub.nds.tls.attacker:transport` - Network I/O layer (shared with TLS-Attacker)
- `de.rub.nds:modifiable-variable` - Runtime value modification framework
- `org.bouncycastle:bcprov-jdk18on` - Cryptographic operations
- `com.beust:jcommander` - CLI argument parsing

## Testing

- **JUnit 5** with **Mockito**
- Unit tests: run during `test` phase, exclude `@Tag("IntegrationTest")` and `@Tag("SlowTest")`
- Integration tests: run during `integration-test` phase via failsafe plugin
- Slow tests: deferred to `integration-test` phase by default (`delayed-slow-tests` profile, active by default)
- Surefire runs tests in parallel (3 forks, parallel by class)

