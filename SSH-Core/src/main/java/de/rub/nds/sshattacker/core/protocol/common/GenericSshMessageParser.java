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
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A generic parser that deserializes any {@link SshMessage} based on its declared {@link SshField}
 * hierarchy. Replaces the need for per-message parser classes.
 *
 * <p>Fields are parsed in declaration order. For variable-length types ({@link SshField.SshString},
 * {@link SshField.SshMpInt}, {@link SshField.SshNameList}), the length is either read from the
 * already-parsed explicit {@link SshField.SshUint32} field or parsed inline when the length field
 * is implicit.
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

        List<SshField> fieldDefinitions = message.getFieldDefinitions();
        Set<String> explicitFieldNames =
                fieldDefinitions.stream().map(SshField::getName).collect(Collectors.toSet());
        for (SshField field : fieldDefinitions) {
            parseField(field, explicitFieldNames);
        }

        LOGGER.trace(
                "Finished parsing {} ({} bytes consumed)",
                () -> message.toCompactString(),
                () -> getPointer() - getStartPoint());
    }

    private void parseField(SshField field, Set<String> explicitFieldNames) {
        LOGGER.trace(
                "Parsing field '{}' (type: {}) at offset {}",
                field::getName,
                field::getType,
                this::getPointer);

        switch (field) {
            case SshField.SshByte f -> {
                byte value = parseByteField();
                message.setField(f, value);
                LOGGER.debug("{}: {}", f::getName, () -> String.format("0x%02X", value));
            }
            case SshField.SshBoolean f -> {
                byte value = parseByteField();
                message.setField(f, value);
                LOGGER.debug(
                        "{}: {} (raw: {})",
                        f::getName,
                        () -> value != 0,
                        () -> String.format("0x%02X", value));
            }
            case SshField.SshUint32 f -> {
                int value = parseIntField();
                message.setField(f, value);
                LOGGER.debug("{}: {}", f::getName, () -> value);
            }
            case SshField.SshUint64 f -> {
                long value = parseLongField();
                message.setField(f, value);
                LOGGER.debug("{}: {}", f::getName, () -> value);
            }
            case SshField.SshBytes f -> {
                int length = f.getLength();
                LOGGER.trace("Fixed byte[{}] field '{}'", () -> length, f::getName);
                byte[] value = parseByteArrayField(length);
                message.setField(f, value);
                LOGGER.debug("{}: {}", f::getName, () -> ArrayConverter.bytesToHexString(value));
            }
            case SshField.SshMpInt f -> {
                int length = parseImplicitLength(f.getLengthField(), explicitFieldNames);
                LOGGER.trace(
                        "Variable-length MPINT '{}', length from '{}' = {}",
                        f::getName,
                        () -> f.getLengthField().getName(),
                        () -> length);
                byte[] value = parseByteArrayField(length);
                message.setField(f, value);
                LOGGER.debug(
                        "{}: ({} bytes) {}",
                        f::getName,
                        () -> value.length,
                        () -> ArrayConverter.bytesToHexString(value));
            }
            case SshField.SshNameList f -> {
                int length = parseImplicitLength(f.getLengthField(), explicitFieldNames);
                LOGGER.trace(
                        "Variable-length NAME_LIST '{}', length from '{}' = {}",
                        f::getName,
                        () -> f.getLengthField().getName(),
                        () -> length);
                String value = parseByteString(length, f.getCharset());
                message.setField(f, value);
                LOGGER.debug("{}: {}", f::getName, () -> backslashEscapeString(value));
            }
            case SshField.SshString f -> {
                int length = parseImplicitLength(f.getLengthField(), explicitFieldNames);
                LOGGER.trace(
                        "Variable-length STRING '{}', length from '{}' = {}",
                        f::getName,
                        () -> f.getLengthField().getName(),
                        () -> length);
                if (f.getCharset() != null) {
                    String value = parseByteString(length, f.getCharset());
                    message.setField(f, value);
                    LOGGER.debug("{}: {}", f::getName, () -> backslashEscapeString(value));
                } else {
                    byte[] value = parseByteArrayField(length);
                    message.setField(f, value);
                    LOGGER.debug(
                            "{}: ({} bytes) {}",
                            f::getName,
                            () -> value.length,
                            () -> ArrayConverter.bytesToHexString(value));
                }
            }
        }
    }

    /**
     * Reads the length for a variable-length field. If the length field is implicit (not in the
     * explicit field definitions list), it is parsed inline from the stream. If explicit, its
     * already-parsed value is read from the message.
     *
     * @param lengthField the UINT32 field holding the byte length
     * @param explicitFieldNames names of all explicitly declared fields
     * @return the length value
     */
    private int parseImplicitLength(
            SshField.SshUint32 lengthField, Set<String> explicitFieldNames) {
        if (!explicitFieldNames.contains(lengthField.getName())) {
            int length = parseIntField();
            message.setField(lengthField, length);
            LOGGER.debug("{} (implicit): {}", lengthField::getName, () -> length);
            return length;
        }
        return message.getField(lengthField).getValue();
    }
}
