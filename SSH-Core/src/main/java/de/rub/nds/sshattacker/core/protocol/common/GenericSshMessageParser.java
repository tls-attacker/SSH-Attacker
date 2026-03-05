/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common;

import java.util.List;
import java.util.function.Supplier;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A generic parser that deserializes any {@link SshMessage} based on its declared {@link
 * SshFieldDefinition}s. Replaces the need for per-message parser classes.
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
        List<SshFieldDefinition> fieldDefinitions = message.getFieldDefinitions();
        for (SshFieldDefinition field : fieldDefinitions) {
            parseField(field);
        }
    }

    private void parseField(SshFieldDefinition field) {
        switch (field.type()) {
            case BYTE -> {
                byte value = parseByteField();
                message.setByteField(field.name(), value);
                LOGGER.debug("{}: {}", field.name(), value);
            }
            case BOOLEAN -> {
                byte value = parseByteField();
                message.setBooleanField(field.name(), value != 0);
                LOGGER.debug("{}: {}", field.name(), value != 0);
            }
            case UINT32 -> {
                int value = parseIntField();
                message.setUint32Field(field.name(), value);
                LOGGER.debug("{}: {}", field.name(), value);
            }
            case UINT64 -> {
                long value = parseLongField();
                message.setUint64Field(field.name(), value);
                LOGGER.debug("{}: {}", field.name(), value);
            }
            case STRING -> {
                int length = parseIntField();
                message.setLengthField(field.name(), length);
                String value = parseByteString(length, field.charset());
                message.setStringField(field.name(), value);
                LOGGER.debug("{} length: {}", field.name(), length);
                LOGGER.debug("{}: {}", field.name(), value);
            }
            case MPINT -> {
                int length = parseIntField();
                message.setLengthField(field.name(), length);
                message.setMpintField(field.name(), parseBigIntField(length));
                LOGGER.debug("{} length: {}", field.name(), length);
            }
            case NAME_LIST -> {
                int length = parseIntField();
                message.setLengthField(field.name(), length);
                String value = parseByteString(length, field.charset());
                message.setStringField(field.name(), value);
                LOGGER.debug("{} length: {}", field.name(), length);
                LOGGER.debug("{}: {}", field.name(), value);
            }
            case RAW_BYTES -> {
                int length = parseIntField();
                message.setLengthField(field.name(), length);
                message.setRawBytesField(field.name(), parseByteArrayField(length));
                LOGGER.debug("{} length: {}", field.name(), length);
            }
        }
    }
}
