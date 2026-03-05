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

    @Override
    public void adjustContext(SshContext context, UserAuthInfoRequestMessage object) {}

    @Override
    public UserAuthInfoRequestMessageParser getParser(byte[] array, SshContext context) {
        return new UserAuthInfoRequestMessageParser(array);
    }

    @Override
    public UserAuthInfoRequestMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new UserAuthInfoRequestMessageParser(array, startPosition);
    }

    public static final UserAuthInfoRequestMessagePreparator PREPARATOR =
            new UserAuthInfoRequestMessagePreparator();

    public static final UserAuthInfoRequestMessageSerializer SERIALIZER =
            new UserAuthInfoRequestMessageSerializer();
}
