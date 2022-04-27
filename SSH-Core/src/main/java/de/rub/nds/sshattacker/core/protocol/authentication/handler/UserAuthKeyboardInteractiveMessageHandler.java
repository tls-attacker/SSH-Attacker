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

    public UserAuthKeyboardInteractiveMessageHandler(SshContext context) {
        super(context);
    }

    public UserAuthKeyboardInteractiveMessageHandler(
            SshContext context, UserAuthKeyboardInteractiveMessage message) {
        super(context, message);
    }
    // ToDo Handle UserAuthKeyboardInteractive
    @Override
    public void adjustContext() {}

    @Override
    public UserAuthKeyboardInteractiveMessageParser getParser(byte[] array) {
        return new UserAuthKeyboardInteractiveMessageParser(array);
    }

    @Override
    public UserAuthKeyboardInteractiveMessageParser getParser(byte[] array, int startPosition) {
        return new UserAuthKeyboardInteractiveMessageParser(array, startPosition);
    }

    @Override
    public UserAuthKeyboardInteractiveMessagePreparator getPreparator() {
        return new UserAuthKeyboardInteractiveMessagePreparator(context.getChooser(), message);
    }

    @Override
    public UserAuthKeyboardInteractiveMessageSerializer getSerializer() {
        return new UserAuthKeyboardInteractiveMessageSerializer(message);
    }
}
