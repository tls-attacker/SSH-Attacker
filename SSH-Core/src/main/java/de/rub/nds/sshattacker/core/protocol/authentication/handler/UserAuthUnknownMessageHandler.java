/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.handler;

import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthUnknownMessage;
import de.rub.nds.sshattacker.core.protocol.authentication.parser.UserAuthUnknownMessageParser;
import de.rub.nds.sshattacker.core.protocol.authentication.preparator.UserAuthUnknownMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.authentication.serializer.UserAuthUnknownMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class UserAuthUnknownMessageHandler extends SshMessageHandler<UserAuthUnknownMessage> {

    @Override
    public void adjustContext(SshContext context, UserAuthUnknownMessage object) {
        // TODO: Handle UserAuthUnknownMessage
    }

    @Override
    public UserAuthUnknownMessageParser getParser(byte[] array, SshContext context) {
        return new UserAuthUnknownMessageParser(array);
    }

    @Override
    public UserAuthUnknownMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new UserAuthUnknownMessageParser(array, startPosition);
    }

    public static final UserAuthUnknownMessagePreparator PREPARATOR =
            new UserAuthUnknownMessagePreparator();

    public static final UserAuthUnknownMessageSerializer SERIALIZER =
            new UserAuthUnknownMessageSerializer();
}
