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
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.state.SshContext;

public class UserAuthUnknownMessageHandler extends SshMessageHandler<UserAuthUnknownMessage> {

    public UserAuthUnknownMessageHandler(SshContext context) {
        super(context);
    }

    public UserAuthUnknownMessageHandler(SshContext context, UserAuthUnknownMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle UserAuthUnknownMessage
    }

    @Override
    public SshMessageParser<UserAuthUnknownMessage> getParser(byte[] array) {
        return new UserAuthUnknownMessageParser(array);
    }

    @Override
    public SshMessageParser<UserAuthUnknownMessage> getParser(byte[] array, int startPosition) {
        return new UserAuthUnknownMessageParser(array, startPosition);
    }

    @Override
    public UserAuthUnknownMessagePreparator getPreparator() {
        return new UserAuthUnknownMessagePreparator(context.getChooser(), message);
    }

    @Override
    public UserAuthUnknownMessageSerializer getSerializer() {
        return new UserAuthUnknownMessageSerializer(message);
    }
}
