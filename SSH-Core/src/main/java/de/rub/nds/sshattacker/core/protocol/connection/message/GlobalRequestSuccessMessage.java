/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.connection.handler.GlobalRequestSuccessMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.parser.GlobalRequestSuccessMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.GlobalRequestSuccessMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.GlobalRequestSuccessMessageSerializer;
import java.io.InputStream;

public class GlobalRequestSuccessMessage extends ChannelMessage<GlobalRequestSuccessMessage> {

    @Override
    public GlobalRequestSuccessMessageHandler getHandler(SshContext context) {
        return new GlobalRequestSuccessMessageHandler(context);
    }

    @Override
    public SshMessageParser<GlobalRequestSuccessMessage> getParser(
            SshContext context, InputStream stream) {
        return new GlobalRequestSuccessMessageParser(stream);
    }

    @Override
    public SshMessagePreparator<GlobalRequestSuccessMessage> getPreparator(SshContext context) {
        return new GlobalRequestSuccessMessagePreparator(context.getChooser(), this);
    }

    @Override
    public SshMessageSerializer<GlobalRequestSuccessMessage> getSerializer(SshContext context) {
        return new GlobalRequestSuccessMessageSerializer(this);
    }

    @Override
    public String toShortString() {
        return "REQ_SUCCESS";
    }
}
