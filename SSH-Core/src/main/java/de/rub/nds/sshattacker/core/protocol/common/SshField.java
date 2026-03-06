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

/**
 * A typed, compile-time-safe field reference for declarative SSH message definitions.
 *
 * <p>Each {@code SshField<V>} carries its name, RFC 4251 data type, and the expected {@link
 * de.rub.nds.modifiablevariable.ModifiableVariable ModifiableVariable} type {@code V}. This
 * prevents common errors like accessing a STRING field with a UINT32 getter — the compiler enforces
 * the correct type.
 *
 * <p>Field instances are created via static factory methods that match RFC 4251 types:
 *
 * <pre>{@code
 * public static final SshField<ModifiableInteger> MSG_LEN = SshField.uint32("msg_length");
 * public static final SshField<ModifiableString> MSG = SshField.string("msg", UTF_8, MSG_LEN);
 *
 * // Usage — compile-time checked:
 * msg.getField(MSG)          // returns ModifiableString
 * msg.setField(MSG, "hello") // works
 * msg.setField(MSG_LEN, "x") // compile error
 * }</pre>
 *
 * @param <V> the {@link de.rub.nds.modifiablevariable.ModifiableVariable ModifiableVariable}
 *     subtype stored for this field
 */
public final class SshField<V> {

    private final String name;
    private final SshDataType type;
    private final Charset charset;
    private final SshField<ModifiableInteger> lengthField;
    private final int fixedLength;

    private SshField(
            String name,
            SshDataType type,
            Charset charset,
            SshField<ModifiableInteger> lengthField,
            int fixedLength) {
        this.name = name;
        this.type = type;
        this.charset = charset;
        this.lengthField = lengthField;
        this.fixedLength = fixedLength;
    }

    // ---- Accessors ----

    /** Returns the field name used as the storage key. */
    public String name() {
        return name;
    }

    /** Returns the RFC 4251 data type. */
    public SshDataType type() {
        return type;
    }

    /**
     * Returns the charset for text encoding/decoding, or {@code null} for binary data and
     * non-string types.
     */
    public Charset charset() {
        return charset;
    }

    /**
     * Returns the UINT32 field that holds the length for variable-length types, or {@code null} for
     * fixed-size types.
     */
    public SshField<ModifiableInteger> lengthField() {
        return lengthField;
    }

    /**
     * Returns the fixed byte count for {@link SshDataType#BYTES} fields, or {@code -1} for all
     * other types.
     */
    public int fixedLength() {
        return fixedLength;
    }

    // ---- Factory methods ----

    /** A single byte ({@code byte}). Stored as {@link ModifiableByte}. */
    public static SshField<ModifiableByte> byte_(String name) {
        return new SshField<>(name, SshDataType.BYTE, null, null, -1);
    }

    /**
     * A boolean value ({@code boolean}). Stored as {@link ModifiableByte} for fine-grained control
     * over the raw byte value.
     */
    public static SshField<ModifiableByte> boolean_(String name) {
        return new SshField<>(name, SshDataType.BOOLEAN, null, null, -1);
    }

    /** A 32-bit unsigned integer ({@code uint32}). Stored as {@link ModifiableInteger}. */
    public static SshField<ModifiableInteger> uint32(String name) {
        return new SshField<>(name, SshDataType.UINT32, null, null, -1);
    }

    /** A 64-bit unsigned integer ({@code uint64}). Stored as {@link ModifiableLong}. */
    public static SshField<ModifiableLong> uint64(String name) {
        return new SshField<>(name, SshDataType.UINT64, null, null, -1);
    }

    /**
     * A fixed-length byte array ({@code byte[n]}). Stored as {@link ModifiableByteArray}.
     *
     * @param fixedLength the exact number of bytes
     */
    public static SshField<ModifiableByteArray> bytes(String name, int fixedLength) {
        return new SshField<>(name, SshDataType.BYTES, null, null, fixedLength);
    }

    /**
     * A variable-length text string ({@code string}) with an implicit length field. The length
     * field is auto-created as {@code name + "_length"} and serialized/parsed inline. It is still
     * accessible via {@link #lengthField()} for independent manipulation.
     *
     * @param charset the charset for encoding/decoding
     */
    public static SshField<ModifiableString> string(String name, Charset charset) {
        SshField<ModifiableInteger> length = uint32(name + "_length");
        return new SshField<>(name, SshDataType.STRING, charset, length, -1);
    }

    /**
     * A variable-length text string ({@code string}). Stored as {@link ModifiableString}. The
     * length is read from / written to the referenced UINT32 field.
     *
     * @param charset the charset for encoding/decoding
     * @param lengthField the UINT32 field holding the byte length
     */
    public static SshField<ModifiableString> string(
            String name, Charset charset, SshField<ModifiableInteger> lengthField) {
        return new SshField<>(name, SshDataType.STRING, charset, lengthField, -1);
    }

    /**
     * A variable-length binary string ({@code string} with no text encoding) with an implicit
     * length field. The length field is auto-created as {@code name + "_length"} and
     * serialized/parsed inline. It is still accessible via {@link #lengthField()} for independent
     * manipulation.
     */
    public static SshField<ModifiableByteArray> string(String name) {
        SshField<ModifiableInteger> length = uint32(name + "_length");
        return new SshField<>(name, SshDataType.STRING, null, length, -1);
    }

    /**
     * A variable-length binary string ({@code string} with no text encoding). Stored as {@link
     * ModifiableByteArray}. The length is read from / written to the referenced UINT32 field.
     *
     * @param lengthField the UINT32 field holding the byte length
     */
    public static SshField<ModifiableByteArray> string(
            String name, SshField<ModifiableInteger> lengthField) {
        return new SshField<>(name, SshDataType.STRING, null, lengthField, -1);
    }

    /**
     * A multiple precision integer ({@code mpint}) with an implicit length field. The length field
     * is auto-created as {@code name + "_length"} and serialized/parsed inline. It is still
     * accessible via {@link #lengthField()} for independent manipulation.
     */
    public static SshField<ModifiableByteArray> mpint(String name) {
        SshField<ModifiableInteger> length = uint32(name + "_length");
        return new SshField<>(name, SshDataType.MPINT, null, length, -1);
    }

    /**
     * A multiple precision integer ({@code mpint}). Stored as {@link ModifiableByteArray}
     * containing the raw two's complement bytes. The length is read from / written to the
     * referenced UINT32 field.
     *
     * @param lengthField the UINT32 field holding the byte length
     */
    public static SshField<ModifiableByteArray> mpint(
            String name, SshField<ModifiableInteger> lengthField) {
        return new SshField<>(name, SshDataType.MPINT, null, lengthField, -1);
    }

    /**
     * A comma-separated list of names ({@code name-list}) with an implicit length field. The length
     * field is auto-created as {@code name + "_length"} and serialized/parsed inline. It is still
     * accessible via {@link #lengthField()} for independent manipulation.
     *
     * @param charset the charset for encoding/decoding (typically US-ASCII)
     */
    public static SshField<ModifiableString> nameList(String name, Charset charset) {
        SshField<ModifiableInteger> length = uint32(name + "_length");
        return new SshField<>(name, SshDataType.NAME_LIST, charset, length, -1);
    }

    /**
     * A comma-separated list of names ({@code name-list}). Stored as {@link ModifiableString}. The
     * length is read from / written to the referenced UINT32 field.
     *
     * @param charset the charset for encoding/decoding (typically US-ASCII)
     * @param lengthField the UINT32 field holding the byte length
     */
    public static SshField<ModifiableString> nameList(
            String name, Charset charset, SshField<ModifiableInteger> lengthField) {
        return new SshField<>(name, SshDataType.NAME_LIST, charset, lengthField, -1);
    }

    @Override
    public String toString() {
        return name + " (" + type + ")";
    }
}
