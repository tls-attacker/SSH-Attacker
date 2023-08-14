/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestHostKeysProveSuccessMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.GlobalRequestHostKeysProveSuccessMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.GlobalRequestHostKeysProveSuccessMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.GlobalRequestHostKeysProveSuccessMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class GlobalRequestHostKeysProveSuccessMessageHandler
        extends SshMessageHandler<GlobalRequestHostKeysProveSuccessMessage> {
    public GlobalRequestHostKeysProveSuccessMessageHandler(SshContext context) {
        super(context);
    }

    public GlobalRequestHostKeysProveSuccessMessageHandler(
            SshContext context, GlobalRequestHostKeysProveSuccessMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle RequestSuccessMessage
    }

    @Override
    public GlobalRequestHostKeysProveSuccessMessageParser getParser(byte[] array) {
        return new GlobalRequestHostKeysProveSuccessMessageParser(array);
    }

    @Override
    public GlobalRequestHostKeysProveSuccessMessageParser getParser(
            byte[] array, int startPosition) {
        return new GlobalRequestHostKeysProveSuccessMessageParser(array, startPosition);
    }

    @Override
    public GlobalRequestHostKeysProveSuccessMessagePreparator getPreparator() {
        return new GlobalRequestHostKeysProveSuccessMessagePreparator(
                context.getChooser(), message);
    }

    @Override
    public GlobalRequestHostKeysProveSuccessMessageSerializer getSerializer() {
        return new GlobalRequestHostKeysProveSuccessMessageSerializer(message);
    }
}
