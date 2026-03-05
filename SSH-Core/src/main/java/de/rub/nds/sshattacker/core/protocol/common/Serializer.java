/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common;

/**
 * The Serializer is responsible to write an Object T into a byte[] form. This is comparable to
 * byte[] serialization.
 *
 * @param <T> Type of the Object to write
 */
public abstract class Serializer<T> {

    /** Constructor for the Serializer */
    protected Serializer() {
        super();
    }

    /**
     * This method is responsible to write the appropriate bytes to the output Stream This should be
     * done by calling the different append methods.
     */
    protected abstract void serializeBytes(T object, SerializerStream output);

    /**
     * Creates the final byte[]
     *
     * @return The final byte[]
     */
    public final byte[] serialize(T object) {
        SerializerStream outputStream = new SerializerStream();
        serializeBytes(object, outputStream);
        return outputStream.toByteArray();
    }
}
