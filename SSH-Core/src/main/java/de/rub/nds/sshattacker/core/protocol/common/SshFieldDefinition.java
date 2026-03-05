/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * Defines a single field in an SSH message, mapping it to an RFC 4251 data type.
 *
 * <p>Field definitions are declared in the message class constructor and drive generic parsing,
 * serialization, and logging. For types with an implicit length prefix ({@link SshDataType#STRING},
 * {@link SshDataType#MPINT}, {@link SshDataType#NAME_LIST}, {@link SshDataType#RAW_BYTES}), the
 * length field is automatically managed and accessible via {@code SshMessage.getStringLengthField}.
 *
 * @param name the field name, should match a {@code public static final String} constant on the
 *     message class
 * @param type the RFC 4251 data type
 * @param charset the charset for encoding/decoding (only relevant for {@link SshDataType#STRING}
 *     and {@link SshDataType#NAME_LIST})
 */
public record SshFieldDefinition(String name, SshDataType type, Charset charset) {

    /**
     * Creates a field definition with the default charset (UTF-8).
     *
     * @param name the field name
     * @param type the RFC 4251 data type
     */
    public SshFieldDefinition(String name, SshDataType type) {
        this(name, type, StandardCharsets.UTF_8);
    }
}
