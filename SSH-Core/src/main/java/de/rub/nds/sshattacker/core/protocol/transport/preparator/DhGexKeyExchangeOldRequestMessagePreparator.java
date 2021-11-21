/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.crypto.hash.DhGexOldExchangeHash;
import de.rub.nds.sshattacker.core.crypto.kex.DhKeyExchange;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeOldRequestMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.util.Random;

public class DhGexKeyExchangeOldRequestMessagePreparator
        extends SshMessagePreparator<DhGexKeyExchangeOldRequestMessage> {

    public DhGexKeyExchangeOldRequestMessagePreparator(
            Chooser chooser, DhGexKeyExchangeOldRequestMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setMessageID(MessageIDConstant.SSH_MSG_KEX_DH_GEX_REQUEST_OLD);
        if (chooser.getContext().getKeyExchangeAlgorithm().isPresent()) {
            DhKeyExchange keyExchange =
                    DhKeyExchange.newInstance(chooser.getContext().getKeyExchangeAlgorithm().get());
            chooser.getContext().setKeyExchangeInstance(keyExchange);
        } else {
            // Maybe raise new "missingContextContents" Exception "Unable to instantiate a new DH
            // key exchange, the negotiated key exchange algorithm is not set");
            DhKeyExchange dhKeyExchange =
                    (DhKeyExchange)
                            DhKeyExchange.newInstance(
                                    (chooser.getRandomKeyExchangeAlgorithm(
                                            new Random(),
                                            chooser.getAllSupportedDH_DHGEKeyExchange())));
            chooser.getContext().setKeyExchangeInstance(dhKeyExchange);
        }

        DhGexOldExchangeHash dhGexOldExchangeHash =
                DhGexOldExchangeHash.from(chooser.getContext().getExchangeHashInstance());
        dhGexOldExchangeHash.setPreferredGroupSize(chooser.getPreferredDHGroupSize());
        chooser.getContext().setExchangeHashInstance(dhGexOldExchangeHash);

        getObject().setPreferredGroupSize(chooser.getPreferredDHGroupSize());
    }
}
