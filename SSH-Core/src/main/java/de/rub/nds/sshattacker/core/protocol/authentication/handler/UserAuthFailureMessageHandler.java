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

    @Override
    public void adjustContext(SshContext context, UserAuthFailureMessage object) {
        // TODO: Handle UserAuthFailureMessage
    }

    @Override
    public UserAuthFailureMessageParser getParser(byte[] array, SshContext context) {
        return new UserAuthFailureMessageParser(array);
    }

    @Override
    public UserAuthFailureMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new UserAuthFailureMessageParser(array, startPosition);
    }

    public static final UserAuthFailureMessagePreparator PREPARATOR =
            new UserAuthFailureMessagePreparator();

    public static final UserAuthFailureMessageSerializer SERIALIZER =
            new UserAuthFailureMessageSerializer();
}
