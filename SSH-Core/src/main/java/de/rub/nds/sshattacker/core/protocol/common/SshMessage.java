/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.modifiablevariable.ModifiableVariable;
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

    private final List<SshField> fieldDefinitions;

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
    private final Map<String, ModifiableVariable<?>> fields = new LinkedHashMap<>();

    // ---- Constructors ----

    /**
     * Declarative constructor. Subclasses pass their message ID and field definitions; parsing,
     * serialization, and field storage are handled generically.
     *
     * @param messageIdConstant the SSH message ID constant
     * @param fieldDefinitions ordered list of field definitions for this message type
     */
    protected SshMessage(MessageIdConstant messageIdConstant, List<SshField> fieldDefinitions) {
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
        messageIdConstant = other.messageIdConstant;
        fieldDefinitions = other.fieldDefinitions;
        messageId = other.messageId != null ? other.messageId.createCopy() : null;
        for (var entry : other.fields.entrySet()) {
            ModifiableVariable<?> value = entry.getValue();
            fields.put(entry.getKey(), value != null ? value.createCopy() : null);
        }
    }

    @Override
    public abstract SshMessage<T> createCopy();

    // ---- Field definitions access ----

    /** Returns the ordered list of field definitions for this message type. */
    public List<SshField> getFieldDefinitions() {
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

    // ---- Typed field getters ----

    /** Returns the value of a BYTE field. */
    public ModifiableByte getField(SshField.SshByte field) {
        return (ModifiableByte) fields.get(field.getName());
    }

    /** Returns the value of a BOOLEAN field. */
    public ModifiableByte getField(SshField.SshBoolean field) {
        return (ModifiableByte) fields.get(field.getName());
    }

    /** Returns the value of a UINT32 field. */
    public ModifiableInteger getField(SshField.SshUint32 field) {
        return (ModifiableInteger) fields.get(field.getName());
    }

    /** Returns the value of a UINT64 field. */
    public ModifiableLong getField(SshField.SshUint64 field) {
        return (ModifiableLong) fields.get(field.getName());
    }

    /** Returns the value of a fixed-length BYTES field. */
    public ModifiableByteArray getField(SshField.SshBytes field) {
        return (ModifiableByteArray) fields.get(field.getName());
    }

    /** Returns the value of an MPINT field. */
    public ModifiableByteArray getField(SshField.SshMpInt field) {
        return (ModifiableByteArray) fields.get(field.getName());
    }

    /** Returns the value of a NAME_LIST field (always text, US-ASCII). */
    public ModifiableString getField(SshField.SshNameList field) {
        return (ModifiableString) fields.get(field.getName());
    }

    /** Returns the value of a text STRING field. */
    public ModifiableString getField(SshField.SshString field) {
        return (ModifiableString) fields.get(field.getName());
    }

    /** Returns the value of a binary STRING field. */
    public ModifiableByteArray getField(SshField.SshBinaryString field) {
        return (ModifiableByteArray) fields.get(field.getName());
    }

    // ---- Typed field setters ----

    /** Sets a BYTE field to a raw byte value. */
    public void setField(SshField.SshByte field, byte value) {
        ModifiableByte current = (ModifiableByte) fields.get(field.getName());
        fields.put(field.getName(), ModifiableVariableFactory.safelySetValue(current, value));
    }

    /** Sets a BYTE field to a {@link ModifiableByte} instance. */
    public void setField(SshField.SshByte field, ModifiableByte value) {
        fields.put(field.getName(), value);
    }

    /** Sets a BOOLEAN field to a raw byte value. */
    public void setField(SshField.SshBoolean field, byte value) {
        ModifiableByte current = (ModifiableByte) fields.get(field.getName());
        fields.put(field.getName(), ModifiableVariableFactory.safelySetValue(current, value));
    }

    /** Sets a BOOLEAN field to a {@link ModifiableByte} instance. */
    public void setField(SshField.SshBoolean field, ModifiableByte value) {
        fields.put(field.getName(), value);
    }

    /** Convenience setter for BOOLEAN fields. Converts {@code true} to 1, {@code false} to 0. */
    public void setField(SshField.SshBoolean field, boolean value) {
        setField(field, value ? (byte) 1 : (byte) 0);
    }

    /** Sets a UINT32 field to an int value. */
    public void setField(SshField.SshUint32 field, int value) {
        ModifiableInteger current = (ModifiableInteger) fields.get(field.getName());
        fields.put(field.getName(), ModifiableVariableFactory.safelySetValue(current, value));
    }

    /** Sets a UINT32 field to a {@link ModifiableInteger} instance. */
    public void setField(SshField.SshUint32 field, ModifiableInteger value) {
        fields.put(field.getName(), value);
    }

    /** Sets a UINT64 field to a long value. */
    public void setField(SshField.SshUint64 field, long value) {
        ModifiableLong current = (ModifiableLong) fields.get(field.getName());
        fields.put(field.getName(), ModifiableVariableFactory.safelySetValue(current, value));
    }

    /** Sets a UINT64 field to a {@link ModifiableLong} instance. */
    public void setField(SshField.SshUint64 field, ModifiableLong value) {
        fields.put(field.getName(), value);
    }

    /** Sets a fixed-length BYTES field to a byte array value. */
    public void setField(SshField.SshBytes field, byte[] value) {
        ModifiableByteArray current = (ModifiableByteArray) fields.get(field.getName());
        fields.put(field.getName(), ModifiableVariableFactory.safelySetValue(current, value));
    }

    /** Sets a fixed-length BYTES field to a {@link ModifiableByteArray} instance. */
    public void setField(SshField.SshBytes field, ModifiableByteArray value) {
        fields.put(field.getName(), value);
    }

    /** Sets a text STRING or NAME_LIST field to a String value. */
    public void setField(SshField.SshString field, String value) {
        setField(field, value, false);
    }

    /**
     * Sets a text STRING or NAME_LIST field. When {@code adjustLength} is true, the implicit length
     * field is updated to match the encoded byte length of the new value.
     */
    public void setField(SshField.SshString field, String value, boolean adjustLength) {
        ModifiableString current = (ModifiableString) fields.get(field.getName());
        ModifiableString updated = ModifiableVariableFactory.safelySetValue(current, value);
        fields.put(field.getName(), updated);
        if (adjustLength) {
            int len = updated.getValue().getBytes(field.getCharset()).length;
            setField(field.getLengthField(), len);
        }
    }

    /** Sets a text STRING or NAME_LIST field to a {@link ModifiableString} instance. */
    public void setField(SshField.SshString field, ModifiableString value) {
        fields.put(field.getName(), value);
    }

    /** Sets a binary STRING field to a byte array value. */
    public void setField(SshField.SshBinaryString field, byte[] value) {
        setField(field, value, false);
    }

    /**
     * Sets a binary STRING field. When {@code adjustLength} is true, the implicit length field is
     * updated to match the byte array length.
     */
    public void setField(SshField.SshBinaryString field, byte[] value, boolean adjustLength) {
        ModifiableByteArray current = (ModifiableByteArray) fields.get(field.getName());
        fields.put(field.getName(), ModifiableVariableFactory.safelySetValue(current, value));
        if (adjustLength) {
            setField(field.getLengthField(), value.length);
        }
    }

    /** Sets a binary STRING field to a {@link ModifiableByteArray} instance. */
    public void setField(SshField.SshBinaryString field, ModifiableByteArray value) {
        fields.put(field.getName(), value);
    }

    /** Sets an MPINT field to a byte array value. */
    public void setField(SshField.SshMpInt field, byte[] value) {
        setField(field, value, false);
    }

    /**
     * Sets an MPINT field. When {@code adjustLength} is true, the implicit length field is updated
     * to match the byte array length.
     */
    public void setField(SshField.SshMpInt field, byte[] value, boolean adjustLength) {
        ModifiableByteArray current = (ModifiableByteArray) fields.get(field.getName());
        fields.put(field.getName(), ModifiableVariableFactory.safelySetValue(current, value));
        if (adjustLength) {
            setField(field.getLengthField(), value.length);
        }
    }

    /** Sets an MPINT field to a {@link ModifiableByteArray} instance. */
    public void setField(SshField.SshMpInt field, ModifiableByteArray value) {
        fields.put(field.getName(), value);
    }

    /** Convenience setter for MPINT fields that accepts a {@link BigInteger}. */
    public void setField(SshField.SshMpInt field, BigInteger value) {
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
                fieldDefinitions.stream().map(SshField::getName).collect(Collectors.toSet());
        for (SshField field : fieldDefinitions) {
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
            SshField field, SerializerStream output, Set<String> explicitFieldNames) {
        LOGGER.trace("Serializing field '{}' (type: {})", field::getName, field::getType);
        switch (field) {
            case SshField.SshByte f -> {
                byte value = ((ModifiableByte) fields.get(f.getName())).getValue();
                output.appendByte(value);
                LOGGER.debug("{}: {}", f::getName, () -> String.format("0x%02X", value));
            }
            case SshField.SshBoolean f -> {
                byte value = ((ModifiableByte) fields.get(f.getName())).getValue();
                output.appendByte(value);
                LOGGER.debug(
                        "{}: {} (raw: {})",
                        f::getName,
                        () -> value != 0,
                        () -> String.format("0x%02X", value));
            }
            case SshField.SshUint32 f -> {
                int value = ((ModifiableInteger) fields.get(f.getName())).getValue();
                output.appendInt(value);
                LOGGER.debug("{}: {}", f::getName, () -> value);
            }
            case SshField.SshUint64 f -> {
                long value = ((ModifiableLong) fields.get(f.getName())).getValue();
                output.appendLong(value);
                LOGGER.debug("{}: {}", f::getName, () -> value);
            }
            case SshField.SshBytes f -> {
                byte[] value = ((ModifiableByteArray) fields.get(f.getName())).getValue();
                output.appendBytes(value);
                LOGGER.debug(
                        "{}: ({} bytes) {}",
                        f::getName,
                        () -> value.length,
                        () -> ArrayConverter.bytesToHexString(value));
            }
            case SshField.SshMpInt f -> {
                serializeImplicitLength(f.getLengthField(), output, explicitFieldNames);
                byte[] value = ((ModifiableByteArray) fields.get(f.getName())).getValue();
                output.appendBytes(value);
                LOGGER.debug(
                        "{}: ({} bytes) {}",
                        f::getName,
                        () -> value.length,
                        () -> ArrayConverter.bytesToHexString(value));
            }
            case SshField.SshBinaryString f -> {
                serializeImplicitLength(f.getLengthField(), output, explicitFieldNames);
                byte[] value = ((ModifiableByteArray) fields.get(f.getName())).getValue();
                output.appendBytes(value);
                LOGGER.debug(
                        "{}: ({} bytes) {}",
                        f::getName,
                        () -> value.length,
                        () -> ArrayConverter.bytesToHexString(value));
            }
            case SshField.SshNameList f -> {
                serializeImplicitLength(f.getLengthField(), output, explicitFieldNames);
                String value = ((ModifiableString) fields.get(f.getName())).getValue();
                output.appendString(value, f.getCharset());
                LOGGER.debug("{}: {}", f::getName, () -> backslashEscapeString(value));
            }
            case SshField.SshString f -> {
                serializeImplicitLength(f.getLengthField(), output, explicitFieldNames);
                String value = ((ModifiableString) fields.get(f.getName())).getValue();
                output.appendString(value, f.getCharset());
                LOGGER.debug("{}: {}", f::getName, () -> backslashEscapeString(value));
            }
        }
    }

    /**
     * Serializes the length field inline if it is not explicitly declared in the field definitions
     * list (i.e., it is an implicit/auto-created length field).
     */
    private void serializeImplicitLength(
            SshField.SshUint32 lengthField,
            SerializerStream output,
            Set<String> explicitFieldNames) {
        if (!explicitFieldNames.contains(lengthField.getName())) {
            int length = ((ModifiableInteger) fields.get(lengthField.getName())).getValue();
            output.appendInt(length);
            LOGGER.debug("{} (implicit): {}", lengthField::getName, () -> length);
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
    public abstract void adjustContext(SshContext context);

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
                return new SshMessageParser<>(array, self::createNewInstance);
            }

            @Override
            public SshMessageParser<T> getParser(
                    byte[] array, int startPosition, SshContext context) {
                return new SshMessageParser<>(array, startPosition, self::createNewInstance);
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
