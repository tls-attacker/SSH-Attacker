/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.crypto.util.OpenSshHostKeyHelper;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestOpenSshHostKeysMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.GlobalRequestOpenSshHostKeysMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.GlobalRequestOpenSshHostKeysMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.GlobalRequestOpenSshHostKeysMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.HashMap;
import java.util.stream.Collectors;

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
        // parses the hostkeyblob and sets the hostkeys in the specified hashmap in context
        context.setServerHostKeys(
                new HashMap<SshPublicKey<?, ?>, Boolean>(
                        OpenSshHostKeyHelper.parseHostkeyBlob(message.getHostKeys().getValue())
                                .stream()
                                .collect(
                                        Collectors.toMap(
                                                sshPublicKey -> sshPublicKey,
                                                sshPublicKey -> Boolean.FALSE // Using Boolean.FALSE
                                                // instead of FALSE
                                                ))));
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
