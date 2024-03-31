/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common;

import de.rub.nds.sshattacker.core.constants.SshMessageConstants;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class Ssh1MessageParser<T extends Ssh1Message<T>> extends ProtocolMessageParser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    public Ssh1MessageParser(InputStream stream) {
        super(stream);
    }

    protected final void parseProtocolMessageContents(T message) {
        parseMessageID(message);
        parseMessageSpecificContents(message);
    }

    private void parseMessageID(T message) {
        message.setMessageId(parseByteField(SshMessageConstants.MESSAGE_ID_LENGTH));
        LOGGER.debug("Parsing MessageID {}", message.getMessageId().getValue());
    }

    protected abstract void parseMessageSpecificContents(T message);
}
