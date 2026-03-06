/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common;

import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.longint.ModifiableLong;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * A compile-time-safe field descriptor for declarative SSH message definitions.
 *
 * <p>The sealed class hierarchy mirrors the RFC 4251 data types. Each subclass carries only the
 * attributes relevant to its type (e.g., {@link SshString} holds a charset and length field, while
 * {@link SshByte} needs neither). The concrete subclass determines which {@link
 * de.rub.nds.modifiablevariable.ModifiableVariable ModifiableVariable} type is stored and which
 * {@link SshMessage#setField setField}/{@link SshMessage#getField getField} overloads apply,
 * preventing type mismatches at compile time.
 *
 * <p>Field instances are created via static factory methods:
 *
 * <pre>{@code
 * public static final SshField.SshString MESSAGE =
 *         SshField.string("message", StandardCharsets.UTF_8);
 *
 * // Usage — compile-time checked:
 * msg.setField(MESSAGE, "hello") // works — SshString accepts String
 * msg.setField(MESSAGE, 42)      // compile error — no setField(SshString, int)
 * }</pre>
 */
public sealed class SshField
        permits SshField.SshByte,
                SshField.SshBoolean,
                SshField.SshUint32,
                SshField.SshUint64,
                SshField.SshBytes,
                SshField.SshString,
                SshField.SshBinaryString,
                SshField.SshMpInt {

    private final String name;
    private final SshDataType type;

    private SshField(String name, SshDataType type) {
        this.name = name;
        this.type = type;
    }

    // ---- Accessors ----

    /** Returns the field name used as the storage key. */
    public String getName() {
        return name;
    }

    /** Returns the RFC 4251 data type. */
    public SshDataType getType() {
        return type;
    }

    // ---- Data Type Classes ----

    /** A single byte field. Stored as {@link ModifiableByte}. */
    public static final class SshByte extends SshField {
        private SshByte(String name) {
            super(name, SshDataType.BYTE);
        }
    }

    /**
     * A boolean field. Stored as {@link ModifiableByte} (rather than a dedicated boolean type) to
     * allow fine-grained control over the raw byte value sent on the wire.
     */
    public static final class SshBoolean extends SshField {
        private SshBoolean(String name) {
            super(name, SshDataType.BOOLEAN);
        }
    }

    /** A 32-bit unsigned integer field. Stored as {@link ModifiableInteger}. */
    public static final class SshUint32 extends SshField {
        private SshUint32(String name) {
            super(name, SshDataType.UINT32);
        }
    }

    /** A 64-bit unsigned integer field. Stored as {@link ModifiableLong}. */
    public static final class SshUint64 extends SshField {
        private SshUint64(String name) {
            super(name, SshDataType.UINT64);
        }
    }

    /**
     * A fixed-length byte array field ({@code byte[n]}). Stored as {@link ModifiableByteArray}. The
     * exact number of bytes is known at declaration time and does not appear on the wire as a
     * separate length prefix.
     */
    public static final class SshBytes extends SshField {

        private final int length;

        private SshBytes(String name, int length) {
            super(name, SshDataType.BYTES);
            this.length = length;
        }

        /** Returns the fixed byte count for this field. */
        public int getLength() {
            return length;
        }
    }

    /**
     * A variable-length text string field. Stored as {@link ModifiableString}. The charset
     * determines how the text is encoded/decoded on the wire.
     *
     * <p>Every string field has an associated {@link SshUint32} length field that holds the byte
     * length of the payload. The length field is auto-created and serialized/parsed inline, but
     * remains independently accessible via {@link #getLengthField()} for manipulation.
     *
     * <p>This class is sealed and extended by {@link SshNameList}.
     *
     * @see SshBinaryString for raw binary data without text encoding
     */
    public static sealed class SshString extends SshField permits SshNameList {

        private final Charset charset;
        private final SshUint32 lengthField;

        private SshString(String name, Charset charset, SshUint32 lengthField) {
            super(name, SshDataType.STRING);
            this.charset = charset;
            this.lengthField = lengthField;
        }

        private SshString(String name, SshDataType type, Charset charset, SshUint32 lengthField) {
            super(name, type);
            this.charset = charset;
            this.lengthField = lengthField;
        }

        /** Returns the charset for text encoding/decoding. */
        public Charset getCharset() {
            return charset;
        }

        /** Returns the implicit {@link SshUint32} field that holds the byte length on the wire. */
        public SshUint32 getLengthField() {
            return lengthField;
        }
    }

    /**
     * A variable-length binary string field (SSH {@code string} with no text encoding). Stored as
     * {@link ModifiableByteArray}. The wire format is identical to {@link SshString} (uint32 length
     * + payload bytes), but the payload is treated as raw binary data.
     *
     * <p>Every binary string field has an associated {@link SshUint32} length field that holds the
     * byte length of the payload. The length field is auto-created and serialized/parsed inline,
     * but remains independently accessible via {@link #getLengthField()} for manipulation.
     *
     * @see SshString for text data with charset encoding
     */
    public static final class SshBinaryString extends SshField {

        private final SshUint32 lengthField;

        private SshBinaryString(String name, SshUint32 lengthField) {
            super(name, SshDataType.STRING);
            this.lengthField = lengthField;
        }

        /** Returns the implicit {@link SshUint32} field that holds the byte length on the wire. */
        public SshUint32 getLengthField() {
            return lengthField;
        }
    }

    /**
     * A multiple precision integer field ({@code mpint}). Stored as {@link ModifiableByteArray}
     * containing the raw two's complement bytes. Like {@link SshString}, every mpint has an
     * associated implicit {@link SshUint32} length field.
     */
    public static final class SshMpInt extends SshField {

        private final SshUint32 lengthField;

        private SshMpInt(String name, SshUint32 lengthField) {
            super(name, SshDataType.MPINT);
            this.lengthField = lengthField;
        }

        /** Returns the implicit {@link SshUint32} field that holds the byte length on the wire. */
        public SshUint32 getLengthField() {
            return lengthField;
        }
    }

    /**
     * A comma-separated name-list field ({@code name-list} per RFC 4251). Always encoded as
     * US-ASCII. Stored as {@link ModifiableString}. Extends {@link SshString} since the wire format
     * is identical (uint32 length + payload bytes).
     */
    public static final class SshNameList extends SshString {
        private SshNameList(String name, SshUint32 lengthField) {
            super(name, SshDataType.NAME_LIST, StandardCharsets.US_ASCII, lengthField);
        }
    }

    // ---- Factory methods ----

    /**
     * Creates a single byte field.
     *
     * @param name the field name
     */
    public static SshByte byte_(String name) {
        return new SshByte(name);
    }

    /**
     * Creates a boolean field.
     *
     * @param name the field name
     */
    public static SshBoolean boolean_(String name) {
        return new SshBoolean(name);
    }

    /**
     * Creates a 32-bit unsigned integer field.
     *
     * @param name the field name
     */
    public static SshUint32 uint32(String name) {
        return new SshUint32(name);
    }

    /**
     * Creates a 64-bit unsigned integer field.
     *
     * @param name the field name
     */
    public static SshUint64 uint64(String name) {
        return new SshUint64(name);
    }

    /**
     * Creates a fixed-length byte array field ({@code byte[n]}).
     *
     * @param name the field name
     * @param length the exact number of bytes
     */
    public static SshBytes bytes(String name, int length) {
        return new SshBytes(name, length);
    }

    /**
     * Creates a variable-length text string field with an implicit length field. The length field
     * is auto-created as {@code name + "_length"} and serialized/parsed inline. It remains
     * accessible via {@link SshString#getLengthField()} for independent manipulation.
     *
     * @param name the field name
     * @param charset the charset for text encoding/decoding (must not be {@code null})
     * @see #binaryString(String) for raw binary data without text encoding
     */
    public static SshString string(String name, Charset charset) {
        SshUint32 length = uint32(name + "_length");
        return new SshString(name, charset, length);
    }

    /**
     * Creates a variable-length binary string field with an implicit length field. The length field
     * is auto-created as {@code name + "_length"} and serialized/parsed inline. It remains
     * accessible via {@link SshBinaryString#getLengthField()} for independent manipulation.
     *
     * @param name the field name
     * @see #string(String, Charset) for text data with charset encoding
     */
    public static SshBinaryString binaryString(String name) {
        SshUint32 length = uint32(name + "_length");
        return new SshBinaryString(name, length);
    }

    /**
     * Creates a multiple precision integer field with an implicit length field. The length field is
     * auto-created as {@code name + "_length"} and serialized/parsed inline. It remains accessible
     * via {@link SshMpInt#getLengthField()} for independent manipulation.
     *
     * @param name the field name
     */
    public static SshMpInt mpint(String name) {
        SshUint32 length = uint32(name + "_length");
        return new SshMpInt(name, length);
    }

    /**
     * Creates a comma-separated name-list field (always US-ASCII) with an implicit length field.
     * The length field is auto-created as {@code name + "_length"} and serialized/parsed inline. It
     * remains accessible via {@link SshString#getLengthField()} for independent manipulation.
     *
     * @param name the field name
     */
    public static SshNameList nameList(String name) {
        SshUint32 length = uint32(name + "_length");
        return new SshNameList(name, length);
    }

    @Override
    public String toString() {
        return name + " (" + type + ")";
    }
}
