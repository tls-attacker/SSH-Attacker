/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.crypto.util.OpenSshHostKeyHelper;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestOpenSshHostKeysProveMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.GlobalRequestOpenSshHostKeysProveMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.GlobalRequestOpenSshHostKeysProveMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.GlobalRequestOpenSshHostKeysProveMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.HashMap;
import java.util.stream.Collectors;

public class GlobalRequestOpenSshHostKeysProveMessageHandler
        extends SshMessageHandler<GlobalRequestOpenSshHostKeysProveMessage> {

    public GlobalRequestOpenSshHostKeysProveMessageHandler(SshContext context) {
        super(context);
    }

    public GlobalRequestOpenSshHostKeysProveMessageHandler(
            SshContext context, GlobalRequestOpenSshHostKeysProveMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // parses the hostkeyblob and sets the hostkeys, that need to be proven to true in the
        // hashmap stored in SshContext
        context.setServerHostKeys(
                new HashMap<SshPublicKey<?, ?>, Boolean>(
                        OpenSshHostKeyHelper.parseHostkeyBlob(message.getHostKeys().getValue())
                                .stream()
                                .collect(
                                        Collectors.toMap(
                                                sshPublicKey -> sshPublicKey,
                                                sshPublicKey -> Boolean.TRUE))));
    }

    @Override
    public GlobalRequestOpenSshHostKeysProveMessageParser getParser(byte[] array) {
        return new GlobalRequestOpenSshHostKeysProveMessageParser(array);
    }

    @Override
    public GlobalRequestOpenSshHostKeysProveMessageParser getParser(
            byte[] array, int startPosition) {
        return new GlobalRequestOpenSshHostKeysProveMessageParser(array, startPosition);
    }

    @Override
    public GlobalRequestOpenSshHostKeysProveMessagePreparator getPreparator() {
        return new GlobalRequestOpenSshHostKeysProveMessagePreparator(
                context.getChooser(), message);
    }

    @Override
    public GlobalRequestOpenSshHostKeysProveMessageSerializer getSerializer() {
        return new GlobalRequestOpenSshHostKeysProveMessageSerializer(message);
    }
}
