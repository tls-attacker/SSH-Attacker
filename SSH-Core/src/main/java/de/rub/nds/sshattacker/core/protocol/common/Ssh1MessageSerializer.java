/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class Ssh1MessageSerializer<T extends Ssh1Message<T>>
        extends ProtocolMessageSerializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    public Ssh1MessageSerializer(T message) {
        super(message);
    }

    // @Override
    protected final void serializeProtocolMessageContents() {
        LOGGER.debug("[bro] while serializing ssh message");
        LOGGER.debug("[bro] id: {}", message.getMessageId().getValue());
        appendByte(message.getMessageId().getValue());
        serializeMessageSpecificContents();
    }

    public abstract void serializeMessageSpecificContents();
}
