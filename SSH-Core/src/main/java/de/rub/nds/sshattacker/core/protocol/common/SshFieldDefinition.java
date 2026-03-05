/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common;

import java.nio.charset.Charset;

/**
 * Defines a single field in an SSH message, mapping it to an RFC 4251 data type.
 *
 * <p>Field definitions are declared as a static list in the message class and drive generic
 * parsing, serialization, and logging. Each definition corresponds to exactly one segment in the
 * wire format. Length prefixes for variable-length types are declared as separate {@link
 * SshDataType#UINT32} fields and referenced via {@link #lengthField()}.
 *
 * @param name the field name, should match a {@code public static final String} constant on the
 *     message class
 * @param type the RFC 4251 data type
 * @param charset the charset for encoding/decoding text strings; {@code null} for binary data or
 *     non-string types
 * @param lengthField the name of the {@link SshDataType#UINT32} field that holds the length for
 *     variable-length types ({@link SshDataType#STRING}, {@link SshDataType#MPINT}, {@link
 *     SshDataType#NAME_LIST}); {@code null} for fixed-size types
 * @param fixedLength the fixed byte count for {@link SshDataType#BYTES} fields; {@code -1} for all
 *     other types
 */
public record SshFieldDefinition(
        String name, SshDataType type, Charset charset, String lengthField, int fixedLength) {

    /**
     * Creates a field definition for simple fixed-size types ({@link SshDataType#BYTE}, {@link
     * SshDataType#BOOLEAN}, {@link SshDataType#UINT32}, {@link SshDataType#UINT64}).
     */
    public SshFieldDefinition(String name, SshDataType type) {
        this(name, type, null, null, -1);
    }

    /**
     * Creates a field definition for a fixed-length byte array ({@link SshDataType#BYTES}).
     *
     * @param fixedLength the exact number of bytes
     */
    public SshFieldDefinition(String name, SshDataType type, int fixedLength) {
        this(name, type, null, null, fixedLength);
    }

    /**
     * Creates a field definition for a variable-length text string ({@link SshDataType#STRING}) or
     * name-list ({@link SshDataType#NAME_LIST}).
     *
     * @param charset the charset for encoding/decoding
     * @param lengthField the name of the UINT32 field holding the length
     */
    public SshFieldDefinition(String name, SshDataType type, Charset charset, String lengthField) {
        this(name, type, charset, lengthField, -1);
    }

    /**
     * Creates a field definition for a variable-length binary type ({@link SshDataType#STRING} with
     * no encoding, or {@link SshDataType#MPINT}).
     *
     * @param lengthField the name of the UINT32 field holding the length
     */
    public SshFieldDefinition(String name, SshDataType type, String lengthField) {
        this(name, type, null, lengthField, -1);
    }
}
