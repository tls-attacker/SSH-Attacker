/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.longint.ModifiableLong;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A generic parser that deserializes any {@link SshMessage} based on its declared {@link
 * SshField}s. Replaces the need for per-message parser classes.
 *
 * <p>Fields are parsed in declaration order. For variable-length types ({@link SshDataType#STRING},
 * {@link SshDataType#MPINT}, {@link SshDataType#NAME_LIST}), the length is read from the
 * already-parsed {@link SshDataType#UINT32} field referenced by {@link SshField#lengthField()}.
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

        List<SshField<?>> fieldDefinitions = message.getFieldDefinitions();
        Set<String> explicitFieldNames =
                fieldDefinitions.stream().map(SshField::name).collect(Collectors.toSet());
        for (SshField<?> field : fieldDefinitions) {
            parseField(field, explicitFieldNames);
        }

        LOGGER.trace(
                "Finished parsing {} ({} bytes consumed)",
                () -> message.toCompactString(),
                () -> getPointer() - getStartPoint());
    }

    @SuppressWarnings("unchecked")
    private void parseField(SshField<?> field, Set<String> explicitFieldNames) {
        LOGGER.trace(
                "Parsing field '{}' (type: {}) at offset {}",
                () -> field.name(),
                () -> field.type(),
                this::getPointer);

        switch (field.type()) {
            case BYTE -> {
                byte value = parseByteField();
                message.setField((SshField<ModifiableByte>) field, value);
                LOGGER.debug("{}: {}", () -> field.name(), () -> String.format("0x%02X", value));
            }
            case BOOLEAN -> {
                byte value = parseByteField();
                message.setField((SshField<ModifiableByte>) field, value);
                LOGGER.debug(
                        "{}: {} (raw: {})",
                        () -> field.name(),
                        () -> value != 0,
                        () -> String.format("0x%02X", value));
            }
            case UINT32 -> {
                int value = parseIntField();
                message.setField((SshField<ModifiableInteger>) field, value);
                LOGGER.debug("{}: {}", () -> field.name(), () -> value);
            }
            case UINT64 -> {
                long value = parseLongField();
                message.setField((SshField<ModifiableLong>) field, value);
                LOGGER.debug("{}: {}", () -> field.name(), () -> value);
            }
            case BYTES -> {
                int length = field.fixedLength();
                LOGGER.trace("Fixed byte[{}] field '{}'", () -> length, () -> field.name());
                byte[] value = parseByteArrayField(length);
                message.setField((SshField<ModifiableByteArray>) field, value);
                LOGGER.debug(
                        "{}: {}", () -> field.name(), () -> ArrayConverter.bytesToHexString(value));
            }
            case STRING -> {
                int length = parseImplicitLength(field, explicitFieldNames);
                LOGGER.trace(
                        "Variable-length STRING '{}', length from '{}' = {}",
                        () -> field.name(),
                        () -> field.lengthField().name(),
                        () -> length);
                if (field.charset() != null) {
                    String value = parseByteString(length, field.charset());
                    message.setField((SshField<ModifiableString>) field, value);
                    LOGGER.debug("{}: {}", () -> field.name(), () -> backslashEscapeString(value));
                } else {
                    byte[] value = parseByteArrayField(length);
                    message.setField((SshField<ModifiableByteArray>) field, value);
                    LOGGER.debug(
                            "{}: ({} bytes) {}",
                            () -> field.name(),
                            () -> value.length,
                            () -> ArrayConverter.bytesToHexString(value));
                }
            }
            case MPINT -> {
                int length = parseImplicitLength(field, explicitFieldNames);
                LOGGER.trace(
                        "Variable-length MPINT '{}', length from '{}' = {}",
                        () -> field.name(),
                        () -> field.lengthField().name(),
                        () -> length);
                byte[] value = parseByteArrayField(length);
                message.setField((SshField<ModifiableByteArray>) field, value);
                LOGGER.debug(
                        "{}: ({} bytes) {}",
                        () -> field.name(),
                        () -> value.length,
                        () -> ArrayConverter.bytesToHexString(value));
            }
            case NAME_LIST -> {
                int length = parseImplicitLength(field, explicitFieldNames);
                LOGGER.trace(
                        "Variable-length NAME_LIST '{}', length from '{}' = {}",
                        () -> field.name(),
                        () -> field.lengthField().name(),
                        () -> length);
                String value = parseByteString(length, field.charset());
                message.setField((SshField<ModifiableString>) field, value);
                LOGGER.debug("{}: {}", () -> field.name(), () -> backslashEscapeString(value));
            }
        }
    }

    /**
     * Reads the length for a variable-length field. If the length field is implicit (not in the
     * explicit field definitions list), it is parsed inline from the stream. If explicit, its
     * already-parsed value is read from the message.
     *
     * @return the length value
     */
    @SuppressWarnings("unchecked")
    private int parseImplicitLength(SshField<?> field, Set<String> explicitFieldNames) {
        if (!explicitFieldNames.contains(field.lengthField().name())) {
            int length = parseIntField();
            message.setField((SshField<ModifiableInteger>) field.lengthField(), length);
            LOGGER.debug("{} (implicit): {}", () -> field.lengthField().name(), () -> length);
            return length;
        }
        return message.getField(field.lengthField()).getValue();
    }
}
