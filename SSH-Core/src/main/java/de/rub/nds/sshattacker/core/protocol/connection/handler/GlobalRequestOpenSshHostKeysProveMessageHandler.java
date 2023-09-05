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

        // private keys have been added to the hashmap in the GlobalRequestHostKeysProveMessage and
        // will be important for signature creation later on
        for (SshPublicKey<?, ?> blobHostKey :
                OpenSshHostKeyHelper.parseHostkeyBlob(message.getHostKeys().getValue())) {
            // following behavior can be seen as a contains method using publicKeyEquality as equal
            // function
            for (SshPublicKey<?, ?> serverHostKey : context.getServerHostKeys().keySet()) {
                if (serverHostKey.publicKeyEquality(blobHostKey)) {
                    context.getServerHostKeys().replace(serverHostKey, Boolean.TRUE);
                }
            }
        }
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
