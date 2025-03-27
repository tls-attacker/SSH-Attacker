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
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.state.SshContext;

public class UserAuthRequestNoneMessageHandler
        extends SshMessageHandler<UserAuthRequestNoneMessage> {

    public UserAuthRequestNoneMessageHandler(SshContext context) {
        super(context);
    }

    public UserAuthRequestNoneMessageHandler(
            SshContext context, UserAuthRequestNoneMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle UserAuthNoneMessage
    }

    @Override
    public SshMessageParser<UserAuthRequestNoneMessage> getParser(byte[] array) {
        return new UserAuthRequestNoneMessageParser(array);
    }

    @Override
    public SshMessageParser<UserAuthRequestNoneMessage> getParser(byte[] array, int startPosition) {
        return new UserAuthRequestNoneMessageParser(array, startPosition);
    }

    @Override
    public UserAuthRequestNoneMessagePreparator getPreparator() {
        return new UserAuthRequestNoneMessagePreparator(context.getChooser(), message);
    }

    @Override
    public UserAuthRequestNoneMessageSerializer getSerializer() {
        return new UserAuthRequestNoneMessageSerializer(message);
    }
}
