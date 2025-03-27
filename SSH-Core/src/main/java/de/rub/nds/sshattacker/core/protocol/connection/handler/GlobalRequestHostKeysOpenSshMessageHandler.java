/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestHostKeysOpenSshMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.GlobalRequestHostKeysOpenSshMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.GlobalRequestHostKeysOpenSshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.GlobalRequestHostKeysOpenSshMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class GlobalRequestHostKeysOpenSshMessageHandler
        extends SshMessageHandler<GlobalRequestHostKeysOpenSshMessage> {

    public GlobalRequestHostKeysOpenSshMessageHandler(SshContext context) {
        super(context);
    }

    public GlobalRequestHostKeysOpenSshMessageHandler(
            SshContext context, GlobalRequestHostKeysOpenSshMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle GlobalRequestHostKeysOpenSshMessage
    }

    @Override
    public GlobalRequestHostKeysOpenSshMessageParser getParser(byte[] array) {
        return new GlobalRequestHostKeysOpenSshMessageParser(array);
    }

    @Override
    public GlobalRequestHostKeysOpenSshMessageParser getParser(byte[] array, int startPosition) {
        return new GlobalRequestHostKeysOpenSshMessageParser(array, startPosition);
    }

    @Override
    public GlobalRequestHostKeysOpenSshMessagePreparator getPreparator() {
        return new GlobalRequestHostKeysOpenSshMessagePreparator(context.getChooser(), message);
    }

    @Override
    public GlobalRequestHostKeysOpenSshMessageSerializer getSerializer() {
        return new GlobalRequestHostKeysOpenSshMessageSerializer(message);
    }
}
