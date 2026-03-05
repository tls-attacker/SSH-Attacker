/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.handler;

import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthRequestPublicKeyMessage;
import de.rub.nds.sshattacker.core.protocol.authentication.parser.UserAuthRequestPublicKeyMessageParser;
import de.rub.nds.sshattacker.core.protocol.authentication.preparator.UserAuthRequestPublicKeyMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.authentication.serializer.UserAuthRequestPublicKeyMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class UserAuthRequestPublicKeyMessageHandler
        extends SshMessageHandler<UserAuthRequestPublicKeyMessage> {

    @Override
    public void adjustContext(SshContext context, UserAuthRequestPublicKeyMessage object) {}

    @Override
    public UserAuthRequestPublicKeyMessageParser getParser(byte[] array, SshContext context) {
        return new UserAuthRequestPublicKeyMessageParser(array);
    }

    @Override
    public UserAuthRequestPublicKeyMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new UserAuthRequestPublicKeyMessageParser(array, startPosition);
    }

    public static final UserAuthRequestPublicKeyMessagePreparator PREPARATOR =
            new UserAuthRequestPublicKeyMessagePreparator();

    public static final UserAuthRequestPublicKeyMessageSerializer SERIALIZER =
            new UserAuthRequestPublicKeyMessageSerializer();
}
