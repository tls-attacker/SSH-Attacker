/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.sshattacker.core.protocol.common.MessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.NewKeysMessage;

public class NewKeysMessageParser extends MessageParser<NewKeysMessage> {

    public NewKeysMessageParser(int startPosition, byte[] array) {
        super(startPosition, array);
    }

    @Override
    protected void parseMessageSpecificPayload(NewKeysMessage msg) {
    }

    @Override
    public NewKeysMessage createMessage() {
        return new NewKeysMessage();
    }
}
