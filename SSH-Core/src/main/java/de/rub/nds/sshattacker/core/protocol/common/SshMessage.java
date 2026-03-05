/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.longint.ModifiableLong;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import jakarta.xml.bind.annotation.XmlType;
import java.math.BigInteger;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlType(namespace = "ssh-attacker")
public abstract class SshMessage<T extends SshMessage<T>> extends ProtocolMessage<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    // ---- Message ID ----

    protected ModifiableByte messageId;
    private final MessageIdConstant messageIdConstant;

    // ---- Declarative field definitions ----

    private final List<SshFieldDefinition> fieldDefinitions;

    /**
     * Stores all declared field values, keyed by field name. The value types per {@link
     * SshDataType} are:
     *
     * <ul>
     *   <li>BYTE, BOOLEAN → {@link ModifiableByte}
     *   <li>UINT32 → {@link ModifiableInteger}
     *   <li>UINT64 → {@link ModifiableLong}
     *   <li>BYTES → {@link ModifiableByteArray}
     *   <li>STRING (charset != null) , NAME_LIST → {@link ModifiableString}
     *   <li>STRING (charset == null), MPINT → {@link ModifiableByteArray}
     * </ul>
     */
    private final Map<String, Object> fields = new LinkedHashMap<>();

    // ---- Constructors ----

    /**
     * Declarative constructor. Subclasses pass their message ID and field definitions; parsing,
     * serialization, and field storage are handled generically.
     *
     * @param messageIdConstant the SSH message ID constant
     * @param fieldDefinitions ordered list of field definitions for this message type
     */
    protected SshMessage(
            MessageIdConstant messageIdConstant, List<SshFieldDefinition> fieldDefinitions) {
        super();
        this.messageIdConstant = messageIdConstant;
        this.fieldDefinitions = fieldDefinitions;
    }

    /**
     * Copy constructor. Copies message ID, field definitions (shared), and all field values (deep
     * copy).
     */
    protected SshMessage(SshMessage<T> other) {
        super(other);
        this.messageIdConstant = other.messageIdConstant;
        this.fieldDefinitions = other.fieldDefinitions;
        this.messageId = other.messageId != null ? other.messageId.createCopy() : null;
        copyFields(other);
    }

    private void copyFields(SshMessage<T> other) {
        for (var entry : other.fields.entrySet()) {
            fields.put(entry.getKey(), copyModifiableVariable(entry.getValue()));
        }
    }

    private static Object copyModifiableVariable(Object value) {
        if (value == null) return null;
        if (value instanceof ModifiableByte v) return v.createCopy();
        if (value instanceof ModifiableInteger v) return v.createCopy();
        if (value instanceof ModifiableLong v) return v.createCopy();
        if (value instanceof ModifiableString v) return v.createCopy();
        if (value instanceof ModifiableByteArray v) return v.createCopy();
        return value;
    }

    @Override
    public abstract SshMessage<T> createCopy();

    // ---- Field definitions access ----

    /** Returns the ordered list of field definitions for this message type. */
    public List<SshFieldDefinition> getFieldDefinitions() {
        return Collections.unmodifiableList(fieldDefinitions);
    }

    // ---- Message ID accessors ----

    public MessageIdConstant getMessageIdConstant() {
        return messageIdConstant;
    }

    public ModifiableByte getMessageId() {
        return messageId;
    }

    public void setMessageId(ModifiableByte messageId) {
        this.messageId = messageId;
    }

    public void setMessageId(byte messageId) {
        this.messageId = ModifiableVariableFactory.safelySetValue(this.messageId, messageId);
    }

    public void setMessageId(MessageIdConstant messageId) {
        setMessageId(messageId.getId());
    }

    // ---- Generic field getters ----

    /** Returns a BYTE or BOOLEAN field value. */
    public ModifiableByte getByteField(String name) {
        return (ModifiableByte) fields.get(name);
    }

    /** Returns a UINT32 field value. */
    public ModifiableInteger getUint32Field(String name) {
        return (ModifiableInteger) fields.get(name);
    }

    /** Returns a UINT64 field value. */
    public ModifiableLong getUint64Field(String name) {
        return (ModifiableLong) fields.get(name);
    }

    /** Returns a text STRING or NAME_LIST field value (charset != null). */
    public ModifiableString getStringField(String name) {
        return (ModifiableString) fields.get(name);
    }

    /** Returns a BYTES, binary STRING (charset == null), or MPINT field value. */
    public ModifiableByteArray getBytesField(String name) {
        return (ModifiableByteArray) fields.get(name);
    }

    // ---- Generic field setters ----

    public void setByteField(String name, byte value) {
        ModifiableByte current = (ModifiableByte) fields.get(name);
        fields.put(name, ModifiableVariableFactory.safelySetValue(current, value));
    }

    public void setByteField(String name, ModifiableByte value) {
        fields.put(name, value);
    }

    /**
     * Convenience setter for BOOLEAN fields. Converts the boolean to a byte (1 for true, 0 for
     * false) and stores it as a {@link ModifiableByte}.
     */
    public void setBooleanField(String name, boolean value) {
        setByteField(name, value ? (byte) 1 : (byte) 0);
    }

    public void setUint32Field(String name, int value) {
        ModifiableInteger current = (ModifiableInteger) fields.get(name);
        fields.put(name, ModifiableVariableFactory.safelySetValue(current, value));
    }

    public void setUint32Field(String name, ModifiableInteger value) {
        fields.put(name, value);
    }

    public void setUint64Field(String name, long value) {
        ModifiableLong current = (ModifiableLong) fields.get(name);
        fields.put(name, ModifiableVariableFactory.safelySetValue(current, value));
    }

    public void setUint64Field(String name, ModifiableLong value) {
        fields.put(name, value);
    }

    public void setStringField(String name, String value) {
        setStringField(name, value, false);
    }

    /**
     * Sets a text STRING field value. When {@code adjustLength} is true, the referenced length
     * field (declared in the {@link SshFieldDefinition}) is updated to match the encoded byte
     * length of the new value.
     */
    public void setStringField(String name, String value, boolean adjustLength) {
        ModifiableString current = (ModifiableString) fields.get(name);
        ModifiableString updated = ModifiableVariableFactory.safelySetValue(current, value);
        fields.put(name, updated);
        if (adjustLength) {
            SshFieldDefinition def = getFieldDefinition(name);
            int len = updated.getValue().getBytes(def.charset()).length;
            setUint32Field(def.lengthField(), len);
        }
    }

    public void setStringField(String name, ModifiableString value) {
        fields.put(name, value);
    }

    public void setBytesField(String name, byte[] value) {
        setBytesField(name, value, false);
    }

    /**
     * Sets a binary STRING, BYTES, or MPINT field value. When {@code adjustLength} is true, the
     * referenced length field (declared in the {@link SshFieldDefinition}) is updated to match the
     * byte array length.
     */
    public void setBytesField(String name, byte[] value, boolean adjustLength) {
        ModifiableByteArray current = (ModifiableByteArray) fields.get(name);
        fields.put(name, ModifiableVariableFactory.safelySetValue(current, value));
        if (adjustLength) {
            SshFieldDefinition def = getFieldDefinition(name);
            setUint32Field(def.lengthField(), value.length);
        }
    }

    public void setBytesField(String name, ModifiableByteArray value) {
        fields.put(name, value);
    }

    /** Convenience setter for MPINT fields that accepts a {@link BigInteger}. */
    public void setMpintField(String name, BigInteger value) {
        setBytesField(name, value.toByteArray());
    }

    // ---- Field definition lookup ----

    private SshFieldDefinition getFieldDefinition(String name) {
        for (SshFieldDefinition def : fieldDefinitions) {
            if (def.name().equals(name)) {
                return def;
            }
        }
        throw new IllegalArgumentException("No field definition for: " + name);
    }

    // ---- Default serialize implementation ----

    @Override
    public byte[] serialize() {
        LOGGER.debug("Serializing {}", this::toCompactString);
        SerializerStream output = new SerializerStream();
        byte msgId = messageId.getValue();
        output.appendByte(msgId);
        LOGGER.debug("Message ID: {} ({})", () -> messageIdConstant, () -> msgId);
        for (SshFieldDefinition field : fieldDefinitions) {
            serializeField(field, output);
        }
        byte[] result = output.toByteArray();
        LOGGER.trace(
                "Serialized {} ({} bytes): {}",
                this::toCompactString,
                () -> result.length,
                () -> ArrayConverter.bytesToHexString(result));
        return result;
    }

    private void serializeField(SshFieldDefinition field, SerializerStream output) {
        LOGGER.trace("Serializing field '{}' (type: {})", () -> field.name(), () -> field.type());
        switch (field.type()) {
            case BYTE -> {
                byte value = getByteField(field.name()).getValue();
                output.appendByte(value);
                LOGGER.debug("{}: {}", () -> field.name(), () -> String.format("0x%02X", value));
            }
            case BOOLEAN -> {
                byte value = getByteField(field.name()).getValue();
                output.appendByte(value);
                LOGGER.debug(
                        "{}: {} (raw: {})",
                        () -> field.name(),
                        () -> value != 0,
                        () -> String.format("0x%02X", value));
            }
            case UINT32 -> {
                int value = getUint32Field(field.name()).getValue();
                output.appendInt(value);
                LOGGER.debug("{}: {}", () -> field.name(), () -> value);
            }
            case UINT64 -> {
                long value = getUint64Field(field.name()).getValue();
                output.appendLong(value);
                LOGGER.debug("{}: {}", () -> field.name(), () -> value);
            }
            case BYTES -> {
                byte[] value = getBytesField(field.name()).getValue();
                output.appendBytes(value);
                LOGGER.debug(
                        "{}: ({} bytes) {}",
                        () -> field.name(),
                        () -> value.length,
                        () -> ArrayConverter.bytesToHexString(value));
            }
            case STRING -> {
                if (field.charset() != null) {
                    String value = getStringField(field.name()).getValue();
                    output.appendString(value, field.charset());
                    LOGGER.debug("{}: {}", () -> field.name(), () -> backslashEscapeString(value));
                } else {
                    byte[] value = getBytesField(field.name()).getValue();
                    output.appendBytes(value);
                    LOGGER.debug(
                            "{}: ({} bytes) {}",
                            () -> field.name(),
                            () -> value.length,
                            () -> ArrayConverter.bytesToHexString(value));
                }
            }
            case MPINT -> {
                byte[] value = getBytesField(field.name()).getValue();
                output.appendBytes(value);
                LOGGER.debug(
                        "{}: ({} bytes) {}",
                        () -> field.name(),
                        () -> value.length,
                        () -> ArrayConverter.bytesToHexString(value));
            }
            case NAME_LIST -> {
                String value = getStringField(field.name()).getValue();
                output.appendString(value, field.charset());
                LOGGER.debug("{}: {}", () -> field.name(), () -> backslashEscapeString(value));
            }
        }
    }

    // ---- Default prepare implementation ----

    @Override
    public void prepare(Chooser chooser) {
        LOGGER.debug("Preparing {}", this::toCompactString);
        LOGGER.trace(
                "Setting message ID to {} ({})",
                () -> messageIdConstant,
                () -> messageIdConstant.getId());
        setMessageId(messageIdConstant);
        prepareMessageContents(chooser);
        LOGGER.trace("Finished preparing {}", this::toCompactString);
    }

    /**
     * Hook for subclasses to set field values during preparation. The message ID is already set
     * before this method is called.
     */
    protected void prepareMessageContents(Chooser chooser) {
        // Override in subclasses
    }

    // ---- Default adjustContext implementation ----

    @Override
    public void adjustContext(SshContext context) {
        // Override in subclasses
    }

    // ---- Handler ----

    @Override
    public ProtocolMessageHandler<T> getHandler() {
        SshMessage<T> self = this;
        return new SshMessageHandler<T>() {
            @Override
            public void adjustContext(SshContext context, T object) {
                object.adjustContext(context);
            }

            @Override
            public SshMessageParser<T> getParser(byte[] array, SshContext context) {
                return new GenericSshMessageParser<>(array, self::createNewInstance);
            }

            @Override
            public SshMessageParser<T> getParser(
                    byte[] array, int startPosition, SshContext context) {
                return new GenericSshMessageParser<>(array, startPosition, self::createNewInstance);
            }
        };
    }

    /**
     * Creates a new empty instance of this message type. Used by the generic parser to instantiate
     * the message before parsing fields into it. Subclasses must implement this by returning {@code
     * new ConcreteMessage()}.
     */
    protected abstract T createNewInstance();

    // ---- toString ----

    @Override
    public String toCompactString() {
        return getClass().getSimpleName();
    }
}
