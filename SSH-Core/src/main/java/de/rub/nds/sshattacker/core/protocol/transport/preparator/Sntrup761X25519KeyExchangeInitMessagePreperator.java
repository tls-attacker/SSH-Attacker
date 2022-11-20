/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.crypto.kex.HybridKeyExchange;
import de.rub.nds.sshattacker.core.crypto.kex.HybridKeyExchangeAgreement;
import de.rub.nds.sshattacker.core.crypto.kex.HybridKeyExchangeEncapsulation;
import de.rub.nds.sshattacker.core.crypto.kex.KeyAgreement;
import de.rub.nds.sshattacker.core.crypto.kex.KeyEncapsulation;
import de.rub.nds.sshattacker.core.crypto.kex.Sntrup761X25519KeyExchange;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.HybridKeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;


import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Sntrup761X25519KeyExchangeInitMessagePreperator
        extends SshMessagePreparator<HybridKeyExchangeInitMessage> {
    private static final Logger LOGGER = LogManager.getLogger();

    public Sntrup761X25519KeyExchangeInitMessagePreperator(
            Chooser chooser, HybridKeyExchangeInitMessage message) {
        super(chooser, message, MessageIdConstant.SSH_MSG_HBR_INIT);
    }

    @Override
    public void prepareMessageSpecificContents() {

        HybridKeyExchange keyExchange = chooser.getHybridKeyExchange();
        KeyAgreement ec25519 = keyExchange.getKeyAgreement();
        KeyEncapsulation sntrup761 = keyExchange.getKeyEncapsulation();

        ec25519.generateLocalKeyPair();
        sntrup761.generateLocalKeyPair();

        byte[] pubKsntrup761 = sntrup761.getLocalKeyPair().getPublic().getEncoded();
        LOGGER.info("PubKey Sntrup: " + ArrayConverter.bytesToHexString(pubKsntrup761));

        byte[] pubKec25519 = ec25519.getLocalKeyPair().getPublic().getEncoded();
        LOGGER.info("PubKey Ec25519: " + ArrayConverter.bytesToHexString(pubKec25519));

        chooser.getContext()
                .getExchangeHashInputHolder()
                .setHybridClientPublicKey(
                        ArrayConverter.concatenate(pubKsntrup761, pubKec25519));
        getObject().setEphemeralECPublicKey(pubKec25519, true);
        getObject().setEphemeralSNTRUPPublicKey(pubKsntrup761, true);
    }
}
