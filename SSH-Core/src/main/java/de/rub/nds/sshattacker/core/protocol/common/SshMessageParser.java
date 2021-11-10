/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common;

import de.rub.nds.sshattacker.core.constants.SshMessageConstants;
import de.rub.nds.sshattacker.core.protocol.connection.parser.*;
import de.rub.nds.sshattacker.core.protocol.transport.parser.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class SshMessageParser<T extends SshMessage<T>> extends ProtocolMessageParser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SshMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected final void parseProtocolMessageContents() {
        parseMessageID();
        parseMessageSpecificContents();
    }

    private void parseMessageID() {
        message.setMessageID(parseByteField(SshMessageConstants.MESSAGE_ID_LENGTH));
    }

    protected abstract void parseMessageSpecificContents();
}
