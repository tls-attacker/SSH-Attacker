/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common;

import de.rub.nds.sshattacker.core.protocol.common.Message;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class MessageSerializer<T extends Message<T>> extends Serializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected final T msg;

    public MessageSerializer(T msg) {
        this.msg = msg;
    }

    @Override
    protected byte[] serializeBytes() {
        appendByte(msg.getMessageID().getValue());
        serializeMessageSpecificPayload();
        return getAlreadySerialized();
    }

    protected abstract byte[] serializeMessageSpecificPayload();

    public static <T extends Message<T>> byte[] delegateSerialization(Message<T> message) {
        return message.getSerializer().serialize();
    }
}
