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
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class UserAuthRequestPasswordMessageHandler
        extends SshMessageHandler<UserAuthRequestPasswordMessage> {

    @Override
    public void adjustContext(SshContext context, UserAuthRequestPasswordMessage object) {
        // TODO: Handle UserAuthRequestPasswordMessage
    }

    @Override
    public UserAuthRequestPasswordMessageParser getParser(byte[] array, SshContext context) {
        return new UserAuthRequestPasswordMessageParser(array);
    }

    @Override
    public UserAuthRequestPasswordMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new UserAuthRequestPasswordMessageParser(array, startPosition);
    }

    public static final UserAuthRequestPasswordMessagePreparator PREPARATOR =
            new UserAuthRequestPasswordMessagePreparator();

    public static final UserAuthRequestPasswordMessageSerializer SERIALIZER =
            new UserAuthRequestPasswordMessageSerializer();
}
