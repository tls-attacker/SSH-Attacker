/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.handler;

import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthKeyboardInteractiveMessage;
import de.rub.nds.sshattacker.core.protocol.authentication.parser.UserAuthKeyboardInteractiveMessageParser;
import de.rub.nds.sshattacker.core.protocol.authentication.preparator.UserAuthKeyboardInteractiveMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.authentication.serializer.UserAuthKeyboardInteractiveMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class UserAuthKeyboardInteractiveMessageHandler
        extends SshMessageHandler<UserAuthKeyboardInteractiveMessage> {

    // ToDo Handle UserAuthKeyboardInteractive
    @Override
    public void adjustContext(SshContext context, UserAuthKeyboardInteractiveMessage object) {}

    @Override
    public UserAuthKeyboardInteractiveMessageParser getParser(byte[] array, SshContext context) {
        return new UserAuthKeyboardInteractiveMessageParser(array);
    }

    @Override
    public UserAuthKeyboardInteractiveMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new UserAuthKeyboardInteractiveMessageParser(array, startPosition);
    }

    public static final UserAuthKeyboardInteractiveMessagePreparator PREPARATOR =
            new UserAuthKeyboardInteractiveMessagePreparator();

    public static final UserAuthKeyboardInteractiveMessageSerializer SERIALIZER =
            new UserAuthKeyboardInteractiveMessageSerializer();
}
