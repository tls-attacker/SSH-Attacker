/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.handler;

import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthInfoResponseMessage;
import de.rub.nds.sshattacker.core.protocol.authentication.parser.UserAuthInfoResponseMessageParser;
import de.rub.nds.sshattacker.core.protocol.authentication.preparator.UserAuthInfoResponseMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.authentication.serializer.UserAuthInfoResponseMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class UserAuthInfoResponseMessageHandler
        extends SshMessageHandler<UserAuthInfoResponseMessage> {

    public UserAuthInfoResponseMessageHandler(SshContext context) {
        super(context);
    }

    public UserAuthInfoResponseMessageHandler(
            SshContext context, UserAuthInfoResponseMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {}

    @Override
    public UserAuthInfoResponseMessageParser getParser(byte[] array) {
        return new UserAuthInfoResponseMessageParser(array);
    }

    @Override
    public UserAuthInfoResponseMessageParser getParser(byte[] array, int startPosition) {
        return new UserAuthInfoResponseMessageParser(array, startPosition);
    }

    public static final UserAuthInfoResponseMessagePreparator PREPARATOR =
            new UserAuthInfoResponseMessagePreparator();

    public static final UserAuthInfoResponseMessageSerializer SERIALIZER =
            new UserAuthInfoResponseMessageSerializer();
}
