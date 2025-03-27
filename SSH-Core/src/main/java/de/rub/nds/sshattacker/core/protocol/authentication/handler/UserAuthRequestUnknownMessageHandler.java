/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.handler;

import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthRequestUnknownMessage;
import de.rub.nds.sshattacker.core.protocol.authentication.parser.UserAuthRequestUnknownMessageParser;
import de.rub.nds.sshattacker.core.protocol.authentication.preparator.UserAuthRequestUnknownMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.authentication.serializer.UserAuthRequestUnknownMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.state.SshContext;

public class UserAuthRequestUnknownMessageHandler
        extends SshMessageHandler<UserAuthRequestUnknownMessage> {

    public UserAuthRequestUnknownMessageHandler(SshContext context) {
        super(context);
    }

    public UserAuthRequestUnknownMessageHandler(
            SshContext context, UserAuthRequestUnknownMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle UserAuthUnknownMessage
    }

    @Override
    public SshMessageParser<UserAuthRequestUnknownMessage> getParser(byte[] array) {
        return new UserAuthRequestUnknownMessageParser(array);
    }

    @Override
    public SshMessageParser<UserAuthRequestUnknownMessage> getParser(
            byte[] array, int startPosition) {
        return new UserAuthRequestUnknownMessageParser(array, startPosition);
    }

    @Override
    public UserAuthRequestUnknownMessagePreparator getPreparator() {
        return new UserAuthRequestUnknownMessagePreparator(context.getChooser(), message);
    }

    @Override
    public UserAuthRequestUnknownMessageSerializer getSerializer() {
        return new UserAuthRequestUnknownMessageSerializer(message);
    }
}
