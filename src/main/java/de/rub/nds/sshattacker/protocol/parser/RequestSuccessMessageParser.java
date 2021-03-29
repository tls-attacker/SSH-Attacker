/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.protocol.parser;

import de.rub.nds.sshattacker.protocol.message.RequestSuccessMessage;

public class RequestSuccessMessageParser extends MessageParser<RequestSuccessMessage> {

    public RequestSuccessMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public RequestSuccessMessage createMessage() {
        return new RequestSuccessMessage();
    }

    @Override
    protected void parseMessageSpecificPayload(RequestSuccessMessage msg) {
        msg.setPayload(parseArrayOrTillEnd(-1));
    }

}
