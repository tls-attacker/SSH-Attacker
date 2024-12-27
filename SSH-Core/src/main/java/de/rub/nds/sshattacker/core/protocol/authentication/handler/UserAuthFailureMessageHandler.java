/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.handler;

import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthFailureMessage;
import de.rub.nds.sshattacker.core.protocol.authentication.parser.UserAuthFailureMessageParser;
import de.rub.nds.sshattacker.core.protocol.authentication.preparator.UserAuthFailureMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.authentication.serializer.UserAuthFailureMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class UserAuthFailureMessageHandler extends SshMessageHandler<UserAuthFailureMessage> {

    public UserAuthFailureMessageHandler(SshContext context) {
        super(context);
    }

    public UserAuthFailureMessageHandler(SshContext context, UserAuthFailureMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle UserAuthFailureMessage
    }

    @Override
    public UserAuthFailureMessageParser getParser(byte[] array) {
        return new UserAuthFailureMessageParser(array);
    }

    @Override
    public UserAuthFailureMessageParser getParser(byte[] array, int startPosition) {
        return new UserAuthFailureMessageParser(array, startPosition);
    }

    public static final UserAuthFailureMessagePreparator PREPARATOR =
            new UserAuthFailureMessagePreparator();

    public static final UserAuthFailureMessageSerializer SERIALIZER =
            new UserAuthFailureMessageSerializer();
}
