/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.string;

import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class StringDataMessageHandler extends ProtocolMessageHandler<StringDataMessage> {

    public StringDataMessageHandler(SshContext context) {
        super(context);
    }

    public StringDataMessageHandler(SshContext context, StringDataMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {}

    @Override
    public StringDataMessageParser getParser(byte[] array) {
        return new StringDataMessageParser(array);
    }

    @Override
    public StringDataMessageParser getParser(byte[] array, int startPosition) {
        return new StringDataMessageParser(array, startPosition);
    }

    @Override
    public StringDataMessagePreparator getPreparator() {
        return new StringDataMessagePreparator(context.getChooser(), message);
    }

    @Override
    public StringDataMessageSerializer getSerializer() {
        return new StringDataMessageSerializer(message);
    }
}
