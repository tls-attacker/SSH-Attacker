/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.transport.handler.NewKeysMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.parser.NewKeysMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.NewKeysMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.NewKeysMessageSerializer;
import java.io.InputStream;

public class NewKeysMessage extends SshMessage<NewKeysMessage> {

    @Override
    public NewKeysMessageHandler getHandler(SshContext context) {
        return new NewKeysMessageHandler(context);
    }

    @Override
    public NewKeysMessageParser getParser(SshContext context, InputStream stream) {
        return new NewKeysMessageParser(stream);
    }

    @Override
    public NewKeysMessagePreparator getPreparator(SshContext context) {
        return new NewKeysMessagePreparator(context.getChooser(), this);
    }

    @Override
    public NewKeysMessageSerializer getSerializer(SshContext context) {
        return new NewKeysMessageSerializer(this);
    }

    @Override
    public String toShortString() {
        return "NEW_KEYS";
    }
}
