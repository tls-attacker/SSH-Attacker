/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.handler;

import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthNoneMessage;
import de.rub.nds.sshattacker.core.protocol.authentication.parser.UserAuthNoneMessageParser;
import de.rub.nds.sshattacker.core.protocol.authentication.preparator.UserAuthNoneMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.authentication.serializer.UserAuthNoneMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class UserAuthNoneMessageHandler extends SshMessageHandler<UserAuthNoneMessage> {

    public UserAuthNoneMessageHandler(SshContext context) {
        super(context);
    }

    public UserAuthNoneMessageHandler(SshContext context, UserAuthNoneMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle UserAuthNoneMessage
    }

    @Override
    public UserAuthNoneMessageParser getParser(byte[] array) {
        return new UserAuthNoneMessageParser(array);
    }

    @Override
    public UserAuthNoneMessageParser getParser(byte[] array, int startPosition) {
        return new UserAuthNoneMessageParser(array, startPosition);
    }

    public static final UserAuthNoneMessagePreparator PREPARATOR =
            new UserAuthNoneMessagePreparator();

    @Override
    public UserAuthNoneMessageSerializer getSerializer() {
        return new UserAuthNoneMessageSerializer(message);
    }
}
