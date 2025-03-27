/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.parser;

import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthRequestNoneMessage;

public class UserAuthRequestNoneMessageParser
        extends UserAuthRequestMessageParser<UserAuthRequestNoneMessage> {

    public UserAuthRequestNoneMessageParser(byte[] array) {
        super(array);
    }

    public UserAuthRequestNoneMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public UserAuthRequestNoneMessage createMessage() {
        return new UserAuthRequestNoneMessage();
    }
}
