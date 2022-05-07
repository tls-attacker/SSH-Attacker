/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.handler;

import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthHostbasedMessage;
import de.rub.nds.sshattacker.core.protocol.authentication.parser.UserAuthHostbasedMessageParser;
import de.rub.nds.sshattacker.core.protocol.authentication.preparator.UserAuthHostbasedMessagePreperator;
import de.rub.nds.sshattacker.core.protocol.authentication.serializer.UserAuthHostbasedMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class UserAuthHostbasedMessageHandler extends SshMessageHandler<UserAuthHostbasedMessage> {

    public UserAuthHostbasedMessageHandler(SshContext context) {
        super(context);
    }

    public UserAuthHostbasedMessageHandler(SshContext context, UserAuthHostbasedMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {}

    @Override
    public UserAuthHostbasedMessageParser getParser(byte[] array) {
        return new UserAuthHostbasedMessageParser(array);
    }

    @Override
    public UserAuthHostbasedMessageParser getParser(byte[] array, int startPosition) {
        return new UserAuthHostbasedMessageParser(array, startPosition);
    }

    @Override
    public UserAuthHostbasedMessagePreperator getPreparator() {
        return new UserAuthHostbasedMessagePreperator(context.getChooser(), message);
    }

    @Override
    public UserAuthHostbasedMessageSerializer getSerializer() {
        return new UserAuthHostbasedMessageSerializer(message);
    }
}
