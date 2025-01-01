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

    @Override
    public void adjustContext(SshContext context, StringDataMessage object) {}

    @Override
    public StringDataMessageParser getParser(byte[] array, SshContext context) {
        return new StringDataMessageParser(array);
    }

    @Override
    public StringDataMessageParser getParser(byte[] array, int startPosition, SshContext context) {
        return new StringDataMessageParser(array, startPosition);
    }

    public static final StringDataMessagePreparator PREPARATOR = new StringDataMessagePreparator();

    public static final StringDataMessageSerializer SERIALIZER = new StringDataMessageSerializer();
}
