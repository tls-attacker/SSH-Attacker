/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.message.RequestSuccessMessage;

public class RequestSuccessMessageParser extends SshMessageParser<RequestSuccessMessage> {

    public RequestSuccessMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public RequestSuccessMessage createMessage() {
        return new RequestSuccessMessage();
    }

    @Override
    protected void parseMessageSpecificContents() {}
}
