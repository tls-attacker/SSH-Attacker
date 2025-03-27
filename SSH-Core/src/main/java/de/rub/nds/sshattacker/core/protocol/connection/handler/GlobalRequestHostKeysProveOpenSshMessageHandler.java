/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestHostKeysProveOpenSshMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.GlobalRequestHostKeysProveOpenSshMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.GlobalRequestHostKeysProveOpenSshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.GlobalRequestHostKeysProveOpenSshMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class GlobalRequestHostKeysProveOpenSshMessageHandler
        extends SshMessageHandler<GlobalRequestHostKeysProveOpenSshMessage> {

    public GlobalRequestHostKeysProveOpenSshMessageHandler(SshContext context) {
        super(context);
    }

    public GlobalRequestHostKeysProveOpenSshMessageHandler(
            SshContext context, GlobalRequestHostKeysProveOpenSshMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle GlobalRequestHostKeysProveOpenSshMessage
    }

    @Override
    public GlobalRequestHostKeysProveOpenSshMessageParser getParser(byte[] array) {
        return new GlobalRequestHostKeysProveOpenSshMessageParser(array);
    }

    @Override
    public GlobalRequestHostKeysProveOpenSshMessageParser getParser(
            byte[] array, int startPosition) {
        return new GlobalRequestHostKeysProveOpenSshMessageParser(array, startPosition);
    }

    @Override
    public GlobalRequestHostKeysProveOpenSshMessagePreparator getPreparator() {
        return new GlobalRequestHostKeysProveOpenSshMessagePreparator(
                context.getChooser(), message);
    }

    @Override
    public GlobalRequestHostKeysProveOpenSshMessageSerializer getSerializer() {
        return new GlobalRequestHostKeysProveOpenSshMessageSerializer(message);
    }
}
