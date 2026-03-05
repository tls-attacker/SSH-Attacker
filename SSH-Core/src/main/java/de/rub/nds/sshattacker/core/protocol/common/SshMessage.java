/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bool.ModifiableBoolean;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.longint.ModifiableLong;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import jakarta.xml.bind.annotation.XmlType;
import java.math.BigInteger;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@XmlType(namespace = "ssh-attacker")
public abstract class SshMessage<T extends SshMessage<T>> extends ProtocolMessage<T> {

    // ---- Message ID ----

    protected ModifiableByte messageId;
    private final MessageIdConstant messageIdConstant;

    // ---- Declarative field definitions ----

    private final List<SshFieldDefinition> fieldDefinitions;

    /**
     * Stores all declared field values, keyed by field name. The value types are:
     *
     * <ul>
     *   <li>BYTE → {@link ModifiableByte}
     *   <li>BOOLEAN → {@link ModifiableBoolean}
     *   <li>UINT32 → {@link ModifiableInteger}
     *   <li>UINT64 → {@link ModifiableLong}
     *   <li>STRING, NAME_LIST → {@link ModifiableString}
     *   <li>MPINT → {@link ModifiableByteArray} (raw two's complement bytes)
     *   <li>RAW_BYTES → {@link ModifiableByteArray}
     * </ul>
     */
    private final Map<String, Object> fields = new LinkedHashMap<>();

    /**
     * Stores auto-managed length fields for length-prefixed types (STRING, MPINT, NAME_LIST,
     * RAW_BYTES). Keyed by the owning field's name.
     */
    private final Map<String, ModifiableInteger> lengthFields = new LinkedHashMap<>();

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
        for (var entry : other.lengthFields.entrySet()) {
            lengthFields.put(
                    entry.getKey(),
                    entry.getValue() != null ? entry.getValue().createCopy() : null);
        }
    }

    @SuppressWarnings("unchecked")
    private static Object copyModifiableVariable(Object value) {
        if (value == null) return null;
        if (value instanceof ModifiableByte v) return v.createCopy();
        if (value instanceof ModifiableBoolean v) return v.createCopy();
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

    public ModifiableByte getByteField(String name) {
        return (ModifiableByte) fields.get(name);
    }

    public ModifiableBoolean getBooleanField(String name) {
        return (ModifiableBoolean) fields.get(name);
    }

    public ModifiableInteger getUint32Field(String name) {
        return (ModifiableInteger) fields.get(name);
    }

    public ModifiableLong getUint64Field(String name) {
        return (ModifiableLong) fields.get(name);
    }

    public ModifiableString getStringField(String name) {
        return (ModifiableString) fields.get(name);
    }

    public ModifiableByteArray getMpintField(String name) {
        return (ModifiableByteArray) fields.get(name);
    }

    public ModifiableByteArray getRawBytesField(String name) {
        return (ModifiableByteArray) fields.get(name);
    }

    /** Returns the auto-managed length field for a length-prefixed type (STRING, MPINT, etc.). */
    public ModifiableInteger getLengthField(String name) {
        return lengthFields.get(name);
    }

    // ---- Generic field setters ----

    public void setByteField(String name, byte value) {
        ModifiableByte current = (ModifiableByte) fields.get(name);
        fields.put(name, ModifiableVariableFactory.safelySetValue(current, value));
    }

    public void setByteField(String name, ModifiableByte value) {
        fields.put(name, value);
    }

    public void setBooleanField(String name, boolean value) {
        ModifiableBoolean current = (ModifiableBoolean) fields.get(name);
        fields.put(name, ModifiableVariableFactory.safelySetValue(current, value));
    }

    public void setBooleanField(String name, ModifiableBoolean value) {
        fields.put(name, value);
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

    public void setStringField(String name, String value, boolean adjustLength) {
        ModifiableString current = (ModifiableString) fields.get(name);
        ModifiableString updated = ModifiableVariableFactory.safelySetValue(current, value);
        fields.put(name, updated);
        if (adjustLength) {
            SshFieldDefinition def = getFieldDefinition(name);
            int len = updated.getValue().getBytes(def.charset()).length;
            setLengthField(name, len);
        }
    }

    public void setStringField(String name, ModifiableString value) {
        fields.put(name, value);
    }

    public void setMpintField(String name, BigInteger value) {
        byte[] bytes = value.toByteArray();
        ModifiableByteArray current = (ModifiableByteArray) fields.get(name);
        fields.put(name, ModifiableVariableFactory.safelySetValue(current, bytes));
    }

    public void setMpintField(String name, ModifiableByteArray value) {
        fields.put(name, value);
    }

    public void setRawBytesField(String name, byte[] value) {
        ModifiableByteArray current = (ModifiableByteArray) fields.get(name);
        fields.put(name, ModifiableVariableFactory.safelySetValue(current, value));
    }

    public void setRawBytesField(String name, ModifiableByteArray value) {
        fields.put(name, value);
    }

    public void setLengthField(String name, int value) {
        ModifiableInteger current = lengthFields.get(name);
        lengthFields.put(name, ModifiableVariableFactory.safelySetValue(current, value));
    }

    public void setLengthField(String name, ModifiableInteger value) {
        lengthFields.put(name, value);
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
        SerializerStream output = new SerializerStream();
        output.appendByte(messageId.getValue());
        for (SshFieldDefinition field : fieldDefinitions) {
            serializeField(field, output);
        }
        return output.toByteArray();
    }

    private void serializeField(SshFieldDefinition field, SerializerStream output) {
        switch (field.type()) {
            case BYTE -> output.appendByte(getByteField(field.name()).getValue());
            case BOOLEAN ->
                    output.appendByte(
                            getBooleanField(field.name()).getValue() ? (byte) 1 : (byte) 0);
            case UINT32 -> output.appendInt(getUint32Field(field.name()).getValue());
            case UINT64 -> output.appendLong(getUint64Field(field.name()).getValue());
            case STRING -> {
                output.appendInt(getLengthField(field.name()).getValue());
                output.appendString(getStringField(field.name()).getValue(), field.charset());
            }
            case MPINT -> {
                output.appendInt(getLengthField(field.name()).getValue());
                output.appendBytes(getMpintField(field.name()).getValue());
            }
            case NAME_LIST -> {
                output.appendInt(getLengthField(field.name()).getValue());
                output.appendString(getStringField(field.name()).getValue(), field.charset());
            }
            case RAW_BYTES -> {
                output.appendInt(getLengthField(field.name()).getValue());
                output.appendBytes(getRawBytesField(field.name()).getValue());
            }
        }
    }

    // ---- Default prepare implementation ----

    @Override
    public void prepare(Chooser chooser) {
        setMessageId(messageIdConstant);
        prepareMessageContents(chooser);
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
