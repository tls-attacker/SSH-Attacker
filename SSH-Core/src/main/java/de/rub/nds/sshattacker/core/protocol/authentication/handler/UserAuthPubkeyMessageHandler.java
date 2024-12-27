/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.handler;

import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPubkeyMessage;
import de.rub.nds.sshattacker.core.protocol.authentication.parser.UserAuthPubkeyMessageParser;
import de.rub.nds.sshattacker.core.protocol.authentication.preparator.UserAuthPubkeyMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.authentication.serializer.UserAuthPubkeyMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class UserAuthPubkeyMessageHandler extends SshMessageHandler<UserAuthPubkeyMessage> {

    public UserAuthPubkeyMessageHandler(SshContext context) {
        super(context);
    }

    public UserAuthPubkeyMessageHandler(SshContext context, UserAuthPubkeyMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {}

    @Override
    public UserAuthPubkeyMessageParser getParser(byte[] array) {
        return new UserAuthPubkeyMessageParser(array);
    }

    @Override
    public UserAuthPubkeyMessageParser getParser(byte[] array, int startPosition) {
        return new UserAuthPubkeyMessageParser(array, startPosition);
    }

    public static final UserAuthPubkeyMessagePreparator PREPARATOR =
            new UserAuthPubkeyMessagePreparator();

    public static final UserAuthPubkeyMessageSerializer SERIALIZER =
            new UserAuthPubkeyMessageSerializer();
}
