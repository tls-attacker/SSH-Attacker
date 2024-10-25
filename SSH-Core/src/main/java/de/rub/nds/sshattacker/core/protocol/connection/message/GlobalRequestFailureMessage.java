/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.connection.handler.GlobalRequestFailureMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.parser.GlobalRequestFailureMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.GlobalRequestFailureMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.GlobalRequestFailureMessageSerializer;
import java.io.InputStream;

public class GlobalRequestFailureMessage extends ChannelMessage<GlobalRequestFailureMessage> {

    @Override
    public GlobalRequestFailureMessageHandler getHandler(SshContext context) {
        return new GlobalRequestFailureMessageHandler(context);
    }

    @Override
    public GlobalRequestFailureMessageParser getParser(SshContext context, InputStream stream) {
        return new GlobalRequestFailureMessageParser(stream);
    }

    @Override
    public GlobalRequestFailureMessagePreparator getPreparator(SshContext context) {
        return new GlobalRequestFailureMessagePreparator(context.getChooser(), this);
    }

    @Override
    public GlobalRequestFailureMessageSerializer getSerializer(SshContext context) {
        return new GlobalRequestFailureMessageSerializer(this);
    }

    @Override
    public String toShortString() {
        return "REQUEST_FAILURE";
    }
}
