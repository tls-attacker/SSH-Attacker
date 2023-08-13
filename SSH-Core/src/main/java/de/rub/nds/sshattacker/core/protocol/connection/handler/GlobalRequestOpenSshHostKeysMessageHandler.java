/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestOpenSshHostKeysMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.GlobalRequestOpenSshHostKeysMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.GlobalRequestOpenSshHostKeysMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.GlobalRequestOpenSshHostKeysMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.KeyParser;

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
    public void adjustContext() {
        // this parses the hostkeyblob and sets the hostkeys in the context
        context.setServerHostKeys(KeyParser.parseHostkeyBlob(message.getHostKeys().getValue()));
    }

    @Override
    public SshMessageParser<GlobalRequestOpenSshHostKeysMessage> getParser(byte[] array) {
        return new GlobalRequestOpenSshHostKeysMessageParser(array);
    }

    @Override
    public SshMessageParser<GlobalRequestOpenSshHostKeysMessage> getParser(
            byte[] array, int startPosition) {
        return new GlobalRequestOpenSshHostKeysMessageParser(array, startPosition);
    }

    @Override
    public SshMessagePreparator<GlobalRequestOpenSshHostKeysMessage> getPreparator() {
        return new GlobalRequestOpenSshHostKeysMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SshMessageSerializer<GlobalRequestOpenSshHostKeysMessage> getSerializer() {
        return new GlobalRequestOpenSshHostKeysMessageSerializer(message);
    }
}
