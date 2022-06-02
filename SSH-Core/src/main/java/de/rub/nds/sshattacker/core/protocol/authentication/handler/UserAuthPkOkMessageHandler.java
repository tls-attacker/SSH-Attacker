/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.handler;

import de.rub.nds.sshattacker.core.exceptions.NotImplementedException;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPkOkMessage;
import de.rub.nds.sshattacker.core.protocol.authentication.parser.UserAuthPkOkMessageParser;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class UserAuthPkOkMessageHandler extends SshMessageHandler<UserAuthPkOkMessage> {

    public UserAuthPkOkMessageHandler(SshContext context) {
        super(context);
    }

    public UserAuthPkOkMessageHandler(SshContext context, UserAuthPkOkMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {}

    @Override
    public UserAuthPkOkMessageParser getParser(byte[] array) {
        return new UserAuthPkOkMessageParser(array);
    }

    @Override
    public UserAuthPkOkMessageParser getParser(byte[] array, int startPosition) {
        return new UserAuthPkOkMessageParser(array, startPosition);
    }

    @Override
    public SshMessagePreparator<UserAuthPkOkMessage> getPreparator() {
        throw new NotImplementedException("UserAuthPkOkMessageHandler::getPreparator");
    }

    @Override
    public SshMessageSerializer<UserAuthPkOkMessage> getSerializer() {
        throw new NotImplementedException("UserAuthPkOkMessageHandler::getSerializer");
    }
}
