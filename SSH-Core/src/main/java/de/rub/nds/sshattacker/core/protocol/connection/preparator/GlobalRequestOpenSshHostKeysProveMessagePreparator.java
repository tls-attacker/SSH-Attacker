/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.GlobalRequestType;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.crypto.util.OpenSshHostKeyHelper;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestOpenSshHostKeysProveMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.util.HashMap;
import java.util.stream.Collectors;

public class GlobalRequestOpenSshHostKeysProveMessagePreparator
        extends GlobalRequestMessagePreparator<GlobalRequestOpenSshHostKeysProveMessage> {

    public GlobalRequestOpenSshHostKeysProveMessagePreparator(
            Chooser chooser, GlobalRequestOpenSshHostKeysProveMessage message) {
        super(chooser, message, GlobalRequestType.HOSTKEYS_PROVE_00_OPENSSH_COM);
    }

    @Override
    protected void prepareGlobalRequestMessageSpecificContents() {
        // default is to prove all host keys
        getObject()
                .setHostKeys(
                        chooser.getContext().getServerHostKeys().keySet().stream()
                                .collect(Collectors.toList()));
        // when preparing the hostkeys-prove-00@openssh.com message, all host keys to be proven are
        // set respectively
        // to true in the hashmap stored in SshContext
        chooser.getContext()
                .setServerHostKeys(
                        new HashMap<SshPublicKey<?, ?>, Boolean>(
                                OpenSshHostKeyHelper.parseHostkeyBlob(
                                                getObject().getHostKeys().getValue())
                                        .stream()
                                        .collect(
                                                Collectors.toMap(
                                                        sshPublicKey -> sshPublicKey,
                                                        sshPublicKey -> Boolean.TRUE))));
        getObject().setWantReply(true);
    }
}
