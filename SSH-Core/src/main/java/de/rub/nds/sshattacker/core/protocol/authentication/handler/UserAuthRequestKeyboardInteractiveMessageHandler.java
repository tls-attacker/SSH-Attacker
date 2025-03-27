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

    public UserAuthRequestKeyboardInteractiveMessageHandler(SshContext context) {
        super(context);
    }

    public UserAuthRequestKeyboardInteractiveMessageHandler(
            SshContext context, UserAuthRequestKeyboardInteractiveMessage message) {
        super(context, message);
    }

    // ToDo Handle UserAuthKeyboardInteractive
    @Override
    public void adjustContext() {}

    @Override
    public UserAuthRequestKeyboardInteractiveMessageParser getParser(byte[] array) {
        return new UserAuthRequestKeyboardInteractiveMessageParser(array);
    }

    @Override
    public UserAuthRequestKeyboardInteractiveMessageParser getParser(
            byte[] array, int startPosition) {
        return new UserAuthRequestKeyboardInteractiveMessageParser(array, startPosition);
    }

    @Override
    public UserAuthRequestKeyboardInteractiveMessagePreparator getPreparator() {
        return new UserAuthRequestKeyboardInteractiveMessagePreparator(
                context.getChooser(), message);
    }

    @Override
    public UserAuthRequestKeyboardInteractiveMessageSerializer getSerializer() {
        return new UserAuthRequestKeyboardInteractiveMessageSerializer(message);
    }
}
