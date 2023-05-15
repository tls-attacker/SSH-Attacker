/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.handler;

import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthInfoRequestMessage;
import de.rub.nds.sshattacker.core.protocol.authentication.parser.UserAuthInfoRequestMessageParser;
import de.rub.nds.sshattacker.core.protocol.authentication.preparator.UserAuthInfoRequestMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.authentication.serializer.UserAuthInfoRequestMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class UserAuthInfoRequestMessageHandler
        extends SshMessageHandler<UserAuthInfoRequestMessage> {

    public UserAuthInfoRequestMessageHandler(SshContext context) {
        super(context);
    }

    public UserAuthInfoRequestMessageHandler(
            SshContext context, UserAuthInfoRequestMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {}

    @Override
    public UserAuthInfoRequestMessageParser getParser(byte[] array) {
        return new UserAuthInfoRequestMessageParser(array);
    }

    @Override
    public UserAuthInfoRequestMessageParser getParser(byte[] array, int startPosition) {
        return new UserAuthInfoRequestMessageParser(array, startPosition);
    }

    @Override
    public UserAuthInfoRequestMessagePreparator getPreparator() {
        return new UserAuthInfoRequestMessagePreparator(context.getChooser(), message);
    }

    @Override
    public UserAuthInfoRequestMessageSerializer getSerializer() {
        return new UserAuthInfoRequestMessageSerializer(message);
    }
}
