/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.message;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.authentication.handler.UserAuthSuccessMessageHandler;
import de.rub.nds.sshattacker.core.protocol.authentication.parser.UserAuthSuccessMessageParser;
import de.rub.nds.sshattacker.core.protocol.authentication.preparator.UserAuthSuccessMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.authentication.serializer.UserAuthSuccessMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import java.io.InputStream;

public class UserAuthSuccessMessage extends SshMessage<UserAuthSuccessMessage> {

    @Override
    public UserAuthSuccessMessageHandler getHandler(SshContext context) {
        return new UserAuthSuccessMessageHandler(context);
    }

    @Override
    public UserAuthSuccessMessageParser getParser(SshContext context, InputStream stream) {
        return new UserAuthSuccessMessageParser(stream);
    }

    /*@Override
    public UserAuthSuccessMessageParser getParser(byte[] array) {
        return new UserAuthSuccessMessageParser(array);
    }

    @Override
    public UserAuthSuccessMessageParser getParser(byte[] array, int startPosition) {
        return new UserAuthSuccessMessageParser(array, startPosition);
    }*/

    @Override
    public UserAuthSuccessMessagePreparator getPreparator(SshContext context) {
        return new UserAuthSuccessMessagePreparator(context.getChooser(), this);
    }

    @Override
    public UserAuthSuccessMessageSerializer getSerializer(SshContext context) {
        return new UserAuthSuccessMessageSerializer(this);
    }

    @Override
    public String toShortString() {
        return "USERAUTH_SUCCESS";
    }
}
