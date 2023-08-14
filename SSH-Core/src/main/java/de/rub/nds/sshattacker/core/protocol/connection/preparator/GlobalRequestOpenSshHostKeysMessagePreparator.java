/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.GlobalRequestType;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestOpenSshHostKeysMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.util.HashMap;
import java.util.stream.Collectors;

public class GlobalRequestOpenSshHostKeysMessagePreparator
        extends GlobalRequestMessagePreparator<GlobalRequestOpenSshHostKeysMessage> {

    public GlobalRequestOpenSshHostKeysMessagePreparator(
            Chooser chooser, GlobalRequestOpenSshHostKeysMessage message) {
        super(chooser, message, GlobalRequestType.HOSTKEYS_00_OPENSSH_COM);
    }

    @Override
    protected void prepareGlobalRequestMessageSpecificContents() {
        getObject().setHostKeys(chooser.getConfig().getHostKeys());
        // initially all server host keys, don't need to be proven, so we set every hashmap value to
        // false
        chooser.getContext()
                .setServerHostKeys(
                        new HashMap<SshPublicKey<?, ?>, Boolean>(
                                chooser.getConfig().getHostKeys().stream()
                                        .collect(
                                                Collectors.toMap(
                                                        sshPublicKey -> sshPublicKey,
                                                        sshPublicKey -> Boolean.FALSE
                                                        // Boolean.FALSE
                                                        // instead of FALSE
                                                        ))));
    }
}
