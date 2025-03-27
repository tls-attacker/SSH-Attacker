/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.handler;

import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthRequestPasswordMessage;
import de.rub.nds.sshattacker.core.protocol.authentication.parser.UserAuthRequestPasswordMessageParser;
import de.rub.nds.sshattacker.core.protocol.authentication.preparator.UserAuthRequestPasswordMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.authentication.serializer.UserAuthRequestPasswordMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.state.SshContext;

public class UserAuthRequestPasswordMessageHandler
        extends SshMessageHandler<UserAuthRequestPasswordMessage> {

    public UserAuthRequestPasswordMessageHandler(SshContext context) {
        super(context);
    }

    public UserAuthRequestPasswordMessageHandler(
            SshContext context, UserAuthRequestPasswordMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle UserAuthPasswordMessage
    }

    @Override
    public SshMessageParser<UserAuthRequestPasswordMessage> getParser(byte[] array) {
        return new UserAuthRequestPasswordMessageParser(array);
    }

    @Override
    public SshMessageParser<UserAuthRequestPasswordMessage> getParser(
            byte[] array, int startPosition) {
        return new UserAuthRequestPasswordMessageParser(array, startPosition);
    }

    @Override
    public UserAuthRequestPasswordMessagePreparator getPreparator() {
        return new UserAuthRequestPasswordMessagePreparator(context.getChooser(), message);
    }

    @Override
    public UserAuthRequestPasswordMessageSerializer getSerializer() {
        return new UserAuthRequestPasswordMessageSerializer(message);
    }
}
