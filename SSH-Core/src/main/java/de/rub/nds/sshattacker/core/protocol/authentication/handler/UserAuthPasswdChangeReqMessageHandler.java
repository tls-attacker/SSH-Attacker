/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.handler;

import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPasswdChangeReqMessage;
import de.rub.nds.sshattacker.core.protocol.authentication.parser.UserAuthPasswdChangeReqMessageParser;
import de.rub.nds.sshattacker.core.protocol.authentication.preparator.UserAuthPasswdChangeReqMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.authentication.serializer.UserAuthPasswdChangeReqMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class UserAuthPasswdChangeReqMessageHandler
        extends SshMessageHandler<UserAuthPasswdChangeReqMessage> {

    @Override
    public void adjustContext(SshContext context, UserAuthPasswdChangeReqMessage object) {
        // TODO: Handle UserAuthPasswdChangeReqMessage
    }

    @Override
    public UserAuthPasswdChangeReqMessageParser getParser(byte[] array, SshContext context) {
        return new UserAuthPasswdChangeReqMessageParser(array);
    }

    @Override
    public UserAuthPasswdChangeReqMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new UserAuthPasswdChangeReqMessageParser(array, startPosition);
    }

    public static final UserAuthPasswdChangeReqMessagePreparator PREPARATOR =
            new UserAuthPasswdChangeReqMessagePreparator();

    public static final UserAuthPasswdChangeReqMessageSerializer SERIALIZER =
            new UserAuthPasswdChangeReqMessageSerializer();
}
