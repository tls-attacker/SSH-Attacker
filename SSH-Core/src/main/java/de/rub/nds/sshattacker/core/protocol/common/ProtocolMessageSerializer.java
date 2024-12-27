/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common;

public abstract class ProtocolMessageSerializer<T extends ProtocolMessage<T>>
        extends Serializer<T> {

    @Override
    protected final void serializeBytes(T object, SerializerStream output) {
        serializeProtocolMessageContents(object, output);
    }

    protected abstract void serializeProtocolMessageContents(T object, SerializerStream output);
}
