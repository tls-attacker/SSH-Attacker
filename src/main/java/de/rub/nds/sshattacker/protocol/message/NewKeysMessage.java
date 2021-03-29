/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.sshattacker.protocol.handler.NewKeysMessageHandler;
import de.rub.nds.sshattacker.protocol.preparator.NewKeysMessagePreparator;
import de.rub.nds.sshattacker.protocol.serializer.NewKeysMessageSerializer;
import de.rub.nds.sshattacker.state.SshContext;

public class NewKeysMessage extends Message<NewKeysMessage> {

    public NewKeysMessage() {
        super();
    }

    @Override
    public String toCompactString() {
        return "NewKeysMessage";
    }

    @Override
    public NewKeysMessageHandler getHandler(SshContext context) {
        return new NewKeysMessageHandler(context);
    }

    @Override
    public NewKeysMessageSerializer getSerializer() {
        return new NewKeysMessageSerializer(this);
    }

    @Override
    public NewKeysMessagePreparator getPreparator(SshContext context) {
        return new NewKeysMessagePreparator(context, this);
    }
}
