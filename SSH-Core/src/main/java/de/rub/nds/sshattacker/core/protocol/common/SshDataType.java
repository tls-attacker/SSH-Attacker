/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common;

/**
 * SSH data types as defined in RFC 4251 Section 5.
 *
 * <p>Each constant represents a primitive data type used in the SSH protocol wire format. The field
 * definitions list in each message maps directly to the wire format: each entry corresponds to
 * exactly one serialized segment, including length prefixes which are declared as separate {@link
 * #UINT32} fields.
 */
public enum SshDataType {

    /** A single byte ({@code byte}). Wire size: 1 byte. Stored as {@code ModifiableByte}. */
    BYTE,

    /**
     * A boolean value ({@code boolean}). Wire size: 1 byte. Stored as {@code ModifiableByte} (not
     * {@code ModifiableBoolean}) to allow fine-grained control over the raw byte value — the SSH
     * wire format uses a full byte, not just 0/1.
     */
    BOOLEAN,

    /**
     * A 32-bit unsigned integer ({@code uint32}). Wire size: 4 bytes, big-endian. Stored as {@code
     * ModifiableInteger}.
     */
    UINT32,

    /**
     * A 64-bit unsigned integer ({@code uint64}). Wire size: 8 bytes, big-endian. Stored as {@code
     * ModifiableLong}.
     */
    UINT64,

    /**
     * A fixed-length byte array ({@code byte[n]}). Wire size: exactly {@code n} bytes, where {@code
     * n} is specified via {@link SshFieldDefinition#fixedLength()}. Stored as {@code
     * ModifiableByteArray}.
     */
    BYTES,

    /**
     * Variable-length data ({@code string} in RFC 4251). The length is read from / written to a
     * separate {@link #UINT32} field referenced by {@link SshFieldDefinition#lengthField()}.
     *
     * <p>When {@link SshFieldDefinition#charset()} is non-null, the data is decoded/encoded as text
     * and stored as {@code ModifiableString}. When the charset is null, the data is treated as raw
     * binary and stored as {@code ModifiableByteArray}.
     */
    STRING,

    /**
     * A multiple precision integer ({@code mpint}). The length is read from / written to a separate
     * {@link #UINT32} field referenced by {@link SshFieldDefinition#lengthField()}. Stored as
     * {@code ModifiableByteArray} containing the raw two's complement, big-endian bytes.
     */
    MPINT,

    /**
     * A comma-separated list of names ({@code name-list}). The length is read from / written to a
     * separate {@link #UINT32} field referenced by {@link SshFieldDefinition#lengthField()}. Stored
     * as {@code ModifiableString}.
     */
    NAME_LIST
}
