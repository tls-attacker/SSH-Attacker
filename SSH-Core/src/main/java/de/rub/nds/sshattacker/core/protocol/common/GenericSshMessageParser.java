/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import java.util.List;
import java.util.function.Supplier;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A generic parser that deserializes any {@link SshMessage} based on its declared {@link
 * SshFieldDefinition}s. Replaces the need for per-message parser classes.
 *
 * <p>Fields are parsed in declaration order. For variable-length types ({@link SshDataType#STRING},
 * {@link SshDataType#MPINT}, {@link SshDataType#NAME_LIST}), the length is read from the
 * already-parsed {@link SshDataType#UINT32} field referenced by {@link
 * SshFieldDefinition#lengthField()}.
 *
 * @param <T> the concrete message type
 */
public class GenericSshMessageParser<T extends SshMessage<T>> extends SshMessageParser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Supplier<T> messageFactory;

    public GenericSshMessageParser(byte[] array, Supplier<T> messageFactory) {
        super(array);
        this.messageFactory = messageFactory;
    }

    public GenericSshMessageParser(byte[] array, int startPosition, Supplier<T> messageFactory) {
        super(array, startPosition);
        this.messageFactory = messageFactory;
    }

    @Override
    public T createMessage() {
        return messageFactory.get();
    }

    @Override
    protected void parseMessageSpecificContents() {
        LOGGER.trace(
                "Parsing {} ({} bytes available at offset {})",
                () -> message.toCompactString(),
                this::getBytesLeft,
                this::getPointer);

        List<SshFieldDefinition> fieldDefinitions = message.getFieldDefinitions();
        for (SshFieldDefinition field : fieldDefinitions) {
            parseField(field);
        }

        LOGGER.trace(
                "Finished parsing {} ({} bytes consumed)",
                () -> message.toCompactString(),
                () -> getPointer() - getStartPoint());
    }

    private void parseField(SshFieldDefinition field) {
        LOGGER.trace(
                "Parsing field '{}' (type: {}) at offset {}",
                () -> field.name(),
                () -> field.type(),
                this::getPointer);

        switch (field.type()) {
            case BYTE -> {
                byte value = parseByteField();
                message.setByteField(field.name(), value);
                LOGGER.debug("{}: {}", () -> field.name(), () -> String.format("0x%02X", value));
            }
            case BOOLEAN -> {
                byte value = parseByteField();
                message.setByteField(field.name(), value);
                LOGGER.debug(
                        "{}: {} (raw: {})",
                        () -> field.name(),
                        () -> value != 0,
                        () -> String.format("0x%02X", value));
            }
            case UINT32 -> {
                int value = parseIntField();
                message.setUint32Field(field.name(), value);
                LOGGER.debug("{}: {}", () -> field.name(), () -> value);
            }
            case UINT64 -> {
                long value = parseLongField();
                message.setUint64Field(field.name(), value);
                LOGGER.debug("{}: {}", () -> field.name(), () -> value);
            }
            case BYTES -> {
                int length = field.fixedLength();
                LOGGER.trace("Fixed byte[{}] field '{}'", () -> length, () -> field.name());
                byte[] value = parseByteArrayField(length);
                message.setBytesField(field.name(), value);
                LOGGER.debug(
                        "{}: {}", () -> field.name(), () -> ArrayConverter.bytesToHexString(value));
            }
            case STRING -> {
                int length = message.getUint32Field(field.lengthField()).getValue();
                LOGGER.trace(
                        "Variable-length STRING '{}', length from '{}' = {}",
                        () -> field.name(),
                        () -> field.lengthField(),
                        () -> length);
                if (field.charset() != null) {
                    String value = parseByteString(length, field.charset());
                    message.setStringField(field.name(), value);
                    LOGGER.debug("{}: {}", () -> field.name(), () -> backslashEscapeString(value));
                } else {
                    byte[] value = parseByteArrayField(length);
                    message.setBytesField(field.name(), value);
                    LOGGER.debug(
                            "{}: ({} bytes) {}",
                            () -> field.name(),
                            () -> value.length,
                            () -> ArrayConverter.bytesToHexString(value));
                }
            }
            case MPINT -> {
                int length = message.getUint32Field(field.lengthField()).getValue();
                LOGGER.trace(
                        "Variable-length MPINT '{}', length from '{}' = {}",
                        () -> field.name(),
                        () -> field.lengthField(),
                        () -> length);
                byte[] value = parseByteArrayField(length);
                message.setBytesField(field.name(), value);
                LOGGER.debug(
                        "{}: ({} bytes) {}",
                        () -> field.name(),
                        () -> value.length,
                        () -> ArrayConverter.bytesToHexString(value));
            }
            case NAME_LIST -> {
                int length = message.getUint32Field(field.lengthField()).getValue();
                LOGGER.trace(
                        "Variable-length NAME_LIST '{}', length from '{}' = {}",
                        () -> field.name(),
                        () -> field.lengthField(),
                        () -> length);
                String value = parseByteString(length, field.charset());
                message.setStringField(field.name(), value);
                LOGGER.debug("{}: {}", () -> field.name(), () -> backslashEscapeString(value));
            }
        }
    }
}
