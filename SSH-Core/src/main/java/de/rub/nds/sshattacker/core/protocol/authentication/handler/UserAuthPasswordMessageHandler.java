/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.handler;

import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPasswordMessage;
import de.rub.nds.sshattacker.core.protocol.authentication.parser.UserAuthPasswordMessageParser;
import de.rub.nds.sshattacker.core.protocol.authentication.preparator.UserAuthPasswordMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.authentication.serializer.UserAuthPasswordMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class UserAuthPasswordMessageHandler extends SshMessageHandler<UserAuthPasswordMessage> {

    public UserAuthPasswordMessageHandler(SshContext context) {
        super(context);
    }

    public UserAuthPasswordMessageHandler(SshContext context, UserAuthPasswordMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle UserAuthPasswordMessage
    }

    @Override
    public UserAuthPasswordMessageParser getParser(byte[] array) {
        return new UserAuthPasswordMessageParser(array);
    }

    @Override
    public UserAuthPasswordMessageParser getParser(byte[] array, int startPosition) {
        return new UserAuthPasswordMessageParser(array, startPosition);
    }

    public static final UserAuthPasswordMessagePreparator PREPARATOR =
            new UserAuthPasswordMessagePreparator();

    public static final UserAuthPasswordMessageSerializer SERIALIZER =
            new UserAuthPasswordMessageSerializer();
}
