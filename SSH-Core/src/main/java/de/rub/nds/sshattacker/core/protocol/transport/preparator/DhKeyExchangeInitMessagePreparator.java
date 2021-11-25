/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.core.constants.KeyExchangeFlowType;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.crypto.hash.DhNamedExchangeHash;
import de.rub.nds.sshattacker.core.crypto.kex.DhKeyExchange;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhKeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.util.Optional;
import java.util.Random;

public class DhKeyExchangeInitMessagePreparator
        extends SshMessagePreparator<DhKeyExchangeInitMessage> {

    public DhKeyExchangeInitMessagePreparator(Chooser chooser, DhKeyExchangeInitMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setMessageID(MessageIDConstant.SSH_MSG_KEXDH_INIT);
        Optional<KeyExchangeAlgorithm> keyExchangeAlgorithm =
                chooser.getContext().getKeyExchangeAlgorithm();
        DhKeyExchange keyExchange;
        if (keyExchangeAlgorithm.isPresent()
                && keyExchangeAlgorithm.get().getFlowType() == KeyExchangeFlowType.DIFFIE_HELLMAN) {
            keyExchange = DhKeyExchange.newInstance(keyExchangeAlgorithm.get());
        } else {
            // Maybe raise new "missingContextContents" Exception "Key exchange algorithm not
            // negotiated or unexpected flow type, unable to generate a local key pair");
            keyExchange =
                    (DhKeyExchange)
                            DhKeyExchange.newInstance(
                                    (chooser.getRandomKeyExchangeAlgorithm(
                                            new Random(), chooser.getAllSupportedDHKeyExchange())));
        }
        if (!(keyExchange.areGroupParametersSet())) {
            keyExchange.setModulus(
                    chooser.getConfig().getDefaultDHGexKeyExchangeGroup().getModulus());
            keyExchange.setGenerator(
                    chooser.getConfig().getDefaultDHGexKeyExchangeGroup().getGenerator());
        }
        ;
        keyExchange.generateLocalKeyPair();
        chooser.getContext().setKeyExchangeInstance(keyExchange);

        DhNamedExchangeHash dhNamedExchangeHash =
                DhNamedExchangeHash.from(chooser.getContext().getExchangeHashInstance());
        dhNamedExchangeHash.setClientDHPublicKey(keyExchange.getLocalKeyPair().getPublic());
        chooser.getContext().setExchangeHashInstance(dhNamedExchangeHash);

        getObject().setPublicKey(keyExchange.getLocalKeyPair().getPublic().getY(), true);
    }
}
