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
import java.util.Set;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlType(namespace = "ssh-attacker")
public abstract class SshMessage<T extends SshMessage<T>> extends ProtocolMessage<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    // ---- Message ID ----

    protected ModifiableByte messageId;
    private final MessageIdConstant messageIdConstant;

    // ---- Declarative field definitions ----

    private final List<SshField<?>> fieldDefinitions;

    /**
     * Stores all declared field values, keyed by field name. The value types per {@link
     * SshDataType} are:
     *
     * <ul>
     *   <li>BYTE, BOOLEAN → {@link ModifiableByte}
     *   <li>UINT32 → {@link ModifiableInteger}
     *   <li>UINT64 → {@link ModifiableLong}
     *   <li>BYTES → {@link ModifiableByteArray}
     *   <li>STRING (charset != null), NAME_LIST → {@link ModifiableString}
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
    protected SshMessage(MessageIdConstant messageIdConstant, List<SshField<?>> fieldDefinitions) {
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
    public List<SshField<?>> getFieldDefinitions() {
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

    // ---- Typed field getter ----

    /**
     * Returns the value of a declared field. The return type is determined by the field's type
     * parameter, ensuring compile-time safety.
     *
     * @param <V> the ModifiableVariable subtype
     * @param field the typed field reference
     * @return the field value, or {@code null} if not yet set
     */
    @SuppressWarnings("unchecked")
    public <V> V getField(SshField<V> field) {
        return (V) fields.get(field.name());
    }

    // ---- Typed field setters ----

    /** Sets a BYTE or BOOLEAN field to a raw byte value. */
    public void setField(SshField<ModifiableByte> field, byte value) {
        ModifiableByte current = (ModifiableByte) fields.get(field.name());
        fields.put(field.name(), ModifiableVariableFactory.safelySetValue(current, value));
    }

    /** Sets a BYTE or BOOLEAN field to a {@link ModifiableByte} instance. */
    public void setField(SshField<ModifiableByte> field, ModifiableByte value) {
        fields.put(field.name(), value);
    }

    /**
     * Convenience setter for BOOLEAN fields. Converts the boolean to a byte (1 for true, 0 for
     * false).
     */
    public void setField(SshField<ModifiableByte> field, boolean value) {
        setField(field, value ? (byte) 1 : (byte) 0);
    }

    /** Sets a UINT32 field to an int value. */
    public void setField(SshField<ModifiableInteger> field, int value) {
        ModifiableInteger current = (ModifiableInteger) fields.get(field.name());
        fields.put(field.name(), ModifiableVariableFactory.safelySetValue(current, value));
    }

    /** Sets a UINT32 field to a {@link ModifiableInteger} instance. */
    public void setField(SshField<ModifiableInteger> field, ModifiableInteger value) {
        fields.put(field.name(), value);
    }

    /** Sets a UINT64 field to a long value. */
    public void setField(SshField<ModifiableLong> field, long value) {
        ModifiableLong current = (ModifiableLong) fields.get(field.name());
        fields.put(field.name(), ModifiableVariableFactory.safelySetValue(current, value));
    }

    /** Sets a UINT64 field to a {@link ModifiableLong} instance. */
    public void setField(SshField<ModifiableLong> field, ModifiableLong value) {
        fields.put(field.name(), value);
    }

    /** Sets a text STRING or NAME_LIST field to a String value. */
    public void setField(SshField<ModifiableString> field, String value) {
        setField(field, value, false);
    }

    /**
     * Sets a text STRING or NAME_LIST field. When {@code adjustLength} is true, the referenced
     * length field is updated to match the encoded byte length of the new value.
     */
    public void setField(SshField<ModifiableString> field, String value, boolean adjustLength) {
        ModifiableString current = (ModifiableString) fields.get(field.name());
        ModifiableString updated = ModifiableVariableFactory.safelySetValue(current, value);
        fields.put(field.name(), updated);
        if (adjustLength && field.lengthField() != null) {
            int len = updated.getValue().getBytes(field.charset()).length;
            setField(field.lengthField(), len);
        }
    }

    /** Sets a text STRING or NAME_LIST field to a {@link ModifiableString} instance. */
    public void setField(SshField<ModifiableString> field, ModifiableString value) {
        fields.put(field.name(), value);
    }

    /** Sets a BYTES, binary STRING, or MPINT field to a byte array value. */
    public void setField(SshField<ModifiableByteArray> field, byte[] value) {
        setField(field, value, false);
    }

    /**
     * Sets a BYTES, binary STRING, or MPINT field. When {@code adjustLength} is true, the
     * referenced length field is updated to match the byte array length.
     */
    public void setField(SshField<ModifiableByteArray> field, byte[] value, boolean adjustLength) {
        ModifiableByteArray current = (ModifiableByteArray) fields.get(field.name());
        fields.put(field.name(), ModifiableVariableFactory.safelySetValue(current, value));
        if (adjustLength && field.lengthField() != null) {
            setField(field.lengthField(), value.length);
        }
    }

    /** Sets a BYTES, binary STRING, or MPINT field to a {@link ModifiableByteArray} instance. */
    public void setField(SshField<ModifiableByteArray> field, ModifiableByteArray value) {
        fields.put(field.name(), value);
    }

    /** Convenience setter for MPINT fields that accepts a {@link BigInteger}. */
    public void setField(SshField<ModifiableByteArray> field, BigInteger value) {
        setField(field, value.toByteArray());
    }

    // ---- Default serialize implementation ----

    @Override
    public byte[] serialize() {
        LOGGER.debug("Serializing {}", this::toCompactString);
        SerializerStream output = new SerializerStream();
        byte msgId = messageId.getValue();
        output.appendByte(msgId);
        LOGGER.debug("Message ID: {} ({})", () -> messageIdConstant, () -> msgId);
        Set<String> explicitFieldNames =
                fieldDefinitions.stream().map(SshField::name).collect(Collectors.toSet());
        for (SshField<?> field : fieldDefinitions) {
            serializeField(field, output, explicitFieldNames);
        }
        byte[] result = output.toByteArray();
        LOGGER.trace(
                "Serialized {} ({} bytes): {}",
                this::toCompactString,
                () -> result.length,
                () -> ArrayConverter.bytesToHexString(result));
        return result;
    }

    private void serializeField(
            SshField<?> field, SerializerStream output, Set<String> explicitFieldNames) {
        LOGGER.trace("Serializing field '{}' (type: {})", () -> field.name(), () -> field.type());
        switch (field.type()) {
            case BYTE -> {
                byte value = ((ModifiableByte) fields.get(field.name())).getValue();
                output.appendByte(value);
                LOGGER.debug("{}: {}", () -> field.name(), () -> String.format("0x%02X", value));
            }
            case BOOLEAN -> {
                byte value = ((ModifiableByte) fields.get(field.name())).getValue();
                output.appendByte(value);
                LOGGER.debug(
                        "{}: {} (raw: {})",
                        () -> field.name(),
                        () -> value != 0,
                        () -> String.format("0x%02X", value));
            }
            case UINT32 -> {
                int value = ((ModifiableInteger) fields.get(field.name())).getValue();
                output.appendInt(value);
                LOGGER.debug("{}: {}", () -> field.name(), () -> value);
            }
            case UINT64 -> {
                long value = ((ModifiableLong) fields.get(field.name())).getValue();
                output.appendLong(value);
                LOGGER.debug("{}: {}", () -> field.name(), () -> value);
            }
            case BYTES -> {
                byte[] value = ((ModifiableByteArray) fields.get(field.name())).getValue();
                output.appendBytes(value);
                LOGGER.debug(
                        "{}: ({} bytes) {}",
                        () -> field.name(),
                        () -> value.length,
                        () -> ArrayConverter.bytesToHexString(value));
            }
            case STRING -> {
                serializeImplicitLength(field, output, explicitFieldNames);
                if (field.charset() != null) {
                    String value = ((ModifiableString) fields.get(field.name())).getValue();
                    output.appendString(value, field.charset());
                    LOGGER.debug("{}: {}", () -> field.name(), () -> backslashEscapeString(value));
                } else {
                    byte[] value = ((ModifiableByteArray) fields.get(field.name())).getValue();
                    output.appendBytes(value);
                    LOGGER.debug(
                            "{}: ({} bytes) {}",
                            () -> field.name(),
                            () -> value.length,
                            () -> ArrayConverter.bytesToHexString(value));
                }
            }
            case MPINT -> {
                serializeImplicitLength(field, output, explicitFieldNames);
                byte[] value = ((ModifiableByteArray) fields.get(field.name())).getValue();
                output.appendBytes(value);
                LOGGER.debug(
                        "{}: ({} bytes) {}",
                        () -> field.name(),
                        () -> value.length,
                        () -> ArrayConverter.bytesToHexString(value));
            }
            case NAME_LIST -> {
                serializeImplicitLength(field, output, explicitFieldNames);
                String value = ((ModifiableString) fields.get(field.name())).getValue();
                output.appendString(value, field.charset());
                LOGGER.debug("{}: {}", () -> field.name(), () -> backslashEscapeString(value));
            }
        }
    }

    /**
     * Serializes the length field inline if it is not explicitly declared in the field definitions
     * list (i.e., it is an implicit/auto-created length field).
     */
    private void serializeImplicitLength(
            SshField<?> field, SerializerStream output, Set<String> explicitFieldNames) {
        if (field.lengthField() != null
                && !explicitFieldNames.contains(field.lengthField().name())) {
            int length = ((ModifiableInteger) fields.get(field.lengthField().name())).getValue();
            output.appendInt(length);
            LOGGER.debug("{} (implicit): {}", () -> field.lengthField().name(), () -> length);
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
