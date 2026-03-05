/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestHostKeysOpenSshMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.GlobalRequestHostKeysOpenSshMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.GlobalRequestHostKeysOpenSshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.GlobalRequestHostKeysOpenSshMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class GlobalRequestHostKeysOpenSshMessageHandler
        extends SshMessageHandler<GlobalRequestHostKeysOpenSshMessage> {

    @Override
    public void adjustContext(SshContext context, GlobalRequestHostKeysOpenSshMessage object) {}

    @Override
    public GlobalRequestHostKeysOpenSshMessageParser getParser(byte[] array, SshContext context) {
        return new GlobalRequestHostKeysOpenSshMessageParser(array);
    }

    @Override
    public GlobalRequestHostKeysOpenSshMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new GlobalRequestHostKeysOpenSshMessageParser(array, startPosition);
    }

    public static final GlobalRequestHostKeysOpenSshMessagePreparator PREPARATOR =
            new GlobalRequestHostKeysOpenSshMessagePreparator();

    public static final GlobalRequestHostKeysOpenSshMessageSerializer SERIALIZER =
            new GlobalRequestHostKeysOpenSshMessageSerializer();
}
