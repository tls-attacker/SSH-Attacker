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

import de.rub.nds.modifiablevariable.util.DataConverter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Parser for {@link SshMessage} types. Deserializes the message ID byte and then parses all
 * declared {@link SshField}s in declaration order.
 *
 * <p>For declarative messages, construct with a {@link Supplier} that creates empty message
 * instances. The field-driven parsing handles all RFC 4251 data types generically. For
 * variable-length types ({@link SshField.SshString}, {@link SshField.SshMpInt}, {@link
 * SshField.SshNameList}), the length is either read from an already-parsed explicit {@link
 * SshField.SshUint32} field or parsed inline when the length field is implicit.
 *
 * <p>This class can be extended for edge cases that require custom parsing logic beyond what the
 * declarative field definitions support.
 *
 * @param <T> the concrete message type
 */
public class SshMessageParser<T extends SshMessage<T>> extends ProtocolMessageParser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Supplier<T> messageFactory;

    /**
     * Creates a parser for a declarative message type.
     *
     * @param array the raw byte array to parse
     * @param messageFactory supplier that creates empty message instances
     */
    public SshMessageParser(byte[] array, Supplier<T> messageFactory) {
        super(array);
        this.messageFactory = messageFactory;
    }

    /**
     * Creates a parser for a declarative message type, starting at the given position.
     *
     * @param array the raw byte array to parse
     * @param startPosition position in the array to start parsing from
     * @param messageFactory supplier that creates empty message instances
     */
    public SshMessageParser(byte[] array, int startPosition, Supplier<T> messageFactory) {
        super(array, startPosition);
        this.messageFactory = messageFactory;
    }

    /**
     * Constructor for subclasses that override {@link #createMessage()} directly.
     *
     * @param array the raw byte array to parse
     */
    protected SshMessageParser(byte[] array) {
        super(array);
        messageFactory = null;
    }

    /**
     * Constructor for subclasses that override {@link #createMessage()} directly.
     *
     * @param array the raw byte array to parse
     * @param startPosition position in the array to start parsing from
     */
    protected SshMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
        messageFactory = null;
    }

    @Override
    protected T createMessage() {
        assert messageFactory != null;
        return messageFactory.get();
    }

    @Override
    protected final void parseProtocolMessageContents() {
        message.setMessageId(parseByteField());
        parseMessageSpecificContents();
    }

    /**
     * Parses the message-specific contents after the message ID byte. The default implementation
     * uses the message's declared {@link SshField} definitions for generic field-driven parsing.
     * Subclasses may override this for custom parsing logic.
     */
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
            case SshField.SshByte fld -> {
                byte value = parseByteField();
                message.setField(fld, value);
                LOGGER.debug("{}: {}", fld::getName, () -> String.format("0x%02X", value));
            }
            case SshField.SshBytes fld -> {
                int length = fld.getLength();
                LOGGER.trace("Fixed byte[{}] field '{}'", () -> length, fld::getName);
                byte[] value = parseByteArrayField(length);
                message.setField(fld, value);
                LOGGER.debug("{}: {}", fld::getName, () -> DataConverter.bytesToHexString(value));
            }
            case SshField.SshBoolean fld -> {
                byte value = parseByteField();
                message.setField(fld, value);
                LOGGER.debug(
                        "{}: {} (raw: {})",
                        fld::getName,
                        () -> value != 0,
                        () -> String.format("0x%02X", value));
            }
            case SshField.SshUint32 fld -> {
                int value = parseIntField();
                message.setField(fld, value);
                LOGGER.debug("{}: {}", fld::getName, () -> value);
            }
            case SshField.SshUint64 fld -> {
                long value = parseLongField();
                message.setField(fld, value);
                LOGGER.debug("{}: {}", fld::getName, () -> value);
            }
            case SshField.SshMpInt fld -> {
                int length = parseImplicitLength(fld.getLengthField(), explicitFieldNames);
                LOGGER.trace(
                        "Variable-length MPINT '{}', length from '{}' = {}",
                        fld::getName,
                        () -> fld.getLengthField().getName(),
                        () -> length);
                byte[] value = parseByteArrayField(length);
                message.setField(fld, value);
                LOGGER.debug(
                        "{}: ({} bytes) {}",
                        fld::getName,
                        () -> value.length,
                        () -> DataConverter.bytesToHexString(value));
            }
            case SshField.SshBinaryString fld -> {
                int length = parseImplicitLength(fld.getLengthField(), explicitFieldNames);
                LOGGER.trace(
                        "Variable-length binary STRING '{}', length from '{}' = {}",
                        fld::getName,
                        () -> fld.getLengthField().getName(),
                        () -> length);
                byte[] value = parseByteArrayField(length);
                message.setField(fld, value);
                LOGGER.debug(
                        "{}: ({} bytes) {}",
                        fld::getName,
                        () -> value.length,
                        () -> DataConverter.bytesToHexString(value));
            }
            case SshField.SshNameList fld -> {
                int length = parseImplicitLength(fld.getLengthField(), explicitFieldNames);
                LOGGER.trace(
                        "Variable-length NAME_LIST '{}', length from '{}' = {}",
                        fld::getName,
                        () -> fld.getLengthField().getName(),
                        () -> length);
                String value = parseByteString(length, fld.getCharset());
                message.setField(fld, value);
                LOGGER.debug("{}: {}", fld::getName, () -> backslashEscapeString(value));
            }
            case SshField.SshString fld -> {
                int length = parseImplicitLength(fld.getLengthField(), explicitFieldNames);
                LOGGER.trace(
                        "Variable-length STRING '{}', length from '{}' = {}",
                        fld::getName,
                        () -> fld.getLengthField().getName(),
                        () -> length);
                String value = parseByteString(length, fld.getCharset());
                message.setField(fld, value);
                LOGGER.debug("{}: {}", fld::getName, () -> backslashEscapeString(value));
            }
            default -> throw new IllegalStateException("Unexpected value: " + field);
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
