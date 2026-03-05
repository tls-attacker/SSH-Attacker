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
 * <p>Each constant represents a primitive data type used in the SSH protocol wire format.
 */
public enum SshDataType {
    /** A single byte ({@code byte}). Wire size: 1 byte. */
    BYTE,

    /** A boolean value stored as a single byte ({@code boolean}). Wire size: 1 byte. */
    BOOLEAN,

    /** A 32-bit unsigned integer ({@code uint32}). Wire size: 4 bytes, big-endian. */
    UINT32,

    /** A 64-bit unsigned integer ({@code uint64}). Wire size: 8 bytes, big-endian. */
    UINT64,

    /**
     * A length-prefixed string ({@code string}). Wire format: uint32 length followed by that many
     * bytes of data. The charset used for encoding/decoding is specified in the field definition.
     */
    STRING,

    /**
     * A multiple precision integer ({@code mpint}). Wire format: uint32 length followed by the
     * value in two's complement, big-endian, with the minimal number of bytes.
     */
    MPINT,

    /**
     * A comma-separated list of names ({@code name-list}). Wire format: uint32 length followed by a
     * comma-separated list of ASCII names.
     */
    NAME_LIST,

    /**
     * A raw byte array with length prefix. Wire format: uint32 length followed by that many bytes.
     * Used for opaque binary data (e.g., signatures, key blobs).
     */
    RAW_BYTES
}
