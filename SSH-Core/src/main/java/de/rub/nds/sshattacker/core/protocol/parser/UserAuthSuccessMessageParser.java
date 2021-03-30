/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.parser;

import de.rub.nds.sshattacker.core.protocol.message.UserAuthSuccessMessage;

public class UserAuthSuccessMessageParser extends MessageParser<UserAuthSuccessMessage> {

    public UserAuthSuccessMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public UserAuthSuccessMessage createMessage() {
        return new UserAuthSuccessMessage();
    }

    @Override
    protected void parseMessageSpecificPayload(UserAuthSuccessMessage msg) {
    }

}
