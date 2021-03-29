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

import de.rub.nds.sshattacker.protocol.message.NewKeysMessage;

public class NewKeysMessageParser extends MessageParser<NewKeysMessage> {

    public NewKeysMessageParser(int startPosition, byte[] array) {
        super(startPosition, array);
    }

    public NewKeysMessage createMessage() {
        return new NewKeysMessage();
    }

    @Override
    protected void parseMessageSpecificPayload(NewKeysMessage msg) {
        // only sets messagetype to NewKeysMessage
        // so this can be void
    }
}
