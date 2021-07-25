/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.protocol.common.MessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.message.RequestFailureMessage;

public class RequestFailureMessageParser extends MessageParser<RequestFailureMessage> {

    public RequestFailureMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public RequestFailureMessage createMessage() {
        return new RequestFailureMessage();
    }

    @Override
    protected void parseMessageSpecificPayload(RequestFailureMessage msg) {
    }

}
