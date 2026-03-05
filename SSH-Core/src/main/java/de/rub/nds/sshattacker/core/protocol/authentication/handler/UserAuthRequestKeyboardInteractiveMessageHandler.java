/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.handler;

import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthRequestKeyboardInteractiveMessage;
import de.rub.nds.sshattacker.core.protocol.authentication.parser.UserAuthRequestKeyboardInteractiveMessageParser;
import de.rub.nds.sshattacker.core.protocol.authentication.preparator.UserAuthRequestKeyboardInteractiveMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.authentication.serializer.UserAuthRequestKeyboardInteractiveMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class UserAuthRequestKeyboardInteractiveMessageHandler
        extends SshMessageHandler<UserAuthRequestKeyboardInteractiveMessage> {

    // ToDo Handle UserAuthRequestKeyboardInteractive
    @Override
    public void adjustContext(
            SshContext context, UserAuthRequestKeyboardInteractiveMessage object) {}

    @Override
    public UserAuthRequestKeyboardInteractiveMessageParser getParser(
            byte[] array, SshContext context) {
        return new UserAuthRequestKeyboardInteractiveMessageParser(array);
    }

    @Override
    public UserAuthRequestKeyboardInteractiveMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new UserAuthRequestKeyboardInteractiveMessageParser(array, startPosition);
    }

    public static final UserAuthRequestKeyboardInteractiveMessagePreparator PREPARATOR =
            new UserAuthRequestKeyboardInteractiveMessagePreparator();

    public static final UserAuthRequestKeyboardInteractiveMessageSerializer SERIALIZER =
            new UserAuthRequestKeyboardInteractiveMessageSerializer();
}
