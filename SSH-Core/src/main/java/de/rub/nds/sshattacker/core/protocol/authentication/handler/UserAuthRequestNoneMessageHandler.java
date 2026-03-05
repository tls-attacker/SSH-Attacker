/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.handler;

import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthRequestNoneMessage;
import de.rub.nds.sshattacker.core.protocol.authentication.parser.UserAuthRequestNoneMessageParser;
import de.rub.nds.sshattacker.core.protocol.authentication.preparator.UserAuthRequestNoneMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.authentication.serializer.UserAuthRequestNoneMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class UserAuthRequestNoneMessageHandler
        extends SshMessageHandler<UserAuthRequestNoneMessage> {

    @Override
    public void adjustContext(SshContext context, UserAuthRequestNoneMessage object) {
        // TODO: Handle UserAuthRequestNoneMessage
    }

    @Override
    public UserAuthRequestNoneMessageParser getParser(byte[] array, SshContext context) {
        return new UserAuthRequestNoneMessageParser(array);
    }

    @Override
    public UserAuthRequestNoneMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new UserAuthRequestNoneMessageParser(array, startPosition);
    }

    public static final UserAuthRequestNoneMessagePreparator PREPARATOR =
            new UserAuthRequestNoneMessagePreparator();

    public static final UserAuthRequestNoneMessageSerializer SERIALIZER =
            new UserAuthRequestNoneMessageSerializer();
}
