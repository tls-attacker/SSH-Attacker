/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.message;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.authentication.handler.UserAuthNoneMessageHandler;
import de.rub.nds.sshattacker.core.protocol.authentication.parser.UserAuthNoneMessageParser;
import de.rub.nds.sshattacker.core.protocol.authentication.preparator.UserAuthNoneMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.authentication.serializer.UserAuthNoneMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import java.io.InputStream;

public class UserAuthNoneMessage extends UserAuthRequestMessage<UserAuthNoneMessage> {

    @Override
    public UserAuthNoneMessageHandler getHandler(SshContext context) {
        return new UserAuthNoneMessageHandler(context);
    }

    @Override
    public SshMessageParser<UserAuthNoneMessage> getParser(SshContext context, InputStream stream) {
        return new UserAuthNoneMessageParser(stream);
    }

    /*
    @Override
    public SshMessageParser<UserAuthNoneMessage> getParser(byte[] array) {
        return new UserAuthNoneMessageParser(array);
    }

    @Override
    public SshMessageParser<UserAuthNoneMessage> getParser(byte[] array, int startPosition) {
        return new UserAuthNoneMessageParser(array, startPosition);
    }*/

    @Override
    public UserAuthNoneMessagePreparator getPreparator(SshContext context) {
        return new UserAuthNoneMessagePreparator(context.getChooser(), this);
    }

    @Override
    public UserAuthNoneMessageSerializer getSerializer(SshContext context) {
        return new UserAuthNoneMessageSerializer(this);
    }

    @Override
    public String toShortString() {
        return "AUTH_NONE";
    }
}
