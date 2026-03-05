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
import de.rub.nds.sshattacker.core.state.SshContext;

public class UserAuthRequestUnknownMessageHandler
        extends SshMessageHandler<UserAuthRequestUnknownMessage> {

    @Override
    public void adjustContext(SshContext context, UserAuthRequestUnknownMessage object) {
        // TODO: Handle UserAuthRequestUnknownMessage
    }

    @Override
    public UserAuthRequestUnknownMessageParser getParser(byte[] array, SshContext context) {
        return new UserAuthRequestUnknownMessageParser(array);
    }

    @Override
    public UserAuthRequestUnknownMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new UserAuthRequestUnknownMessageParser(array, startPosition);
    }

    public static final UserAuthRequestUnknownMessagePreparator PREPARATOR =
            new UserAuthRequestUnknownMessagePreparator();

    public static final UserAuthRequestUnknownMessageSerializer SERIALIZER =
            new UserAuthRequestUnknownMessageSerializer();
}
