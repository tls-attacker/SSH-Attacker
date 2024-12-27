/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestOpenSshHostKeysMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.GlobalRequestOpenSshHostKeysMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.GlobalRequestOpenSshHostKeysMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.GlobalRequestOpenSshHostKeysMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class GlobalRequestOpenSshHostKeysMessageHandler
        extends SshMessageHandler<GlobalRequestOpenSshHostKeysMessage> {

    public GlobalRequestOpenSshHostKeysMessageHandler(SshContext context) {
        super(context);
    }

    public GlobalRequestOpenSshHostKeysMessageHandler(
            SshContext context, GlobalRequestOpenSshHostKeysMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {}

    @Override
    public GlobalRequestOpenSshHostKeysMessageParser getParser(byte[] array) {
        return new GlobalRequestOpenSshHostKeysMessageParser(array);
    }

    @Override
    public GlobalRequestOpenSshHostKeysMessageParser getParser(byte[] array, int startPosition) {
        return new GlobalRequestOpenSshHostKeysMessageParser(array, startPosition);
    }

    public static final GlobalRequestOpenSshHostKeysMessagePreparator PREPARATOR =
            new GlobalRequestOpenSshHostKeysMessagePreparator();

    @Override
    public GlobalRequestOpenSshHostKeysMessageSerializer getSerializer() {
        return new GlobalRequestOpenSshHostKeysMessageSerializer(message);
    }
}
