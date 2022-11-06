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
import de.rub.nds.sshattacker.core.crypto.kex.HybridKeyExchangeAgreement;
import de.rub.nds.sshattacker.core.crypto.kex.HybridKeyExchangeEncapsulation;
import de.rub.nds.sshattacker.core.crypto.kex.Sntrup761X25519KeyExchange;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.Sntrup761X25519KeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Sntrup761X25519KeyExchangeInitMessagePreperator
        extends SshMessagePreparator<Sntrup761X25519KeyExchangeInitMessage> {
    private static final Logger LOGGER = LogManager.getLogger();

    public Sntrup761X25519KeyExchangeInitMessagePreperator(
            Chooser chooser, Sntrup761X25519KeyExchangeInitMessage message) {
        super(chooser, message, MessageIdConstant.SSH_MSG_KEX_SNTRUP761_X25519_INIT);
    }

    @Override
    public void prepareMessageSpecificContents() {

        Sntrup761X25519KeyExchange keyExchange = chooser.getSntrup761X25591KeyExchange();
        HybridKeyExchangeAgreement ec25519 = keyExchange.getKeyAgreement("ec25519");
        HybridKeyExchangeEncapsulation sntrup761 = keyExchange.getKeyEncapsulation("sntrup761");

        ec25519.generateLocalKeyPair();
        sntrup761.generateLocalKeyPair();

        byte[] pubKsntrup761 = sntrup761.getLocalKeyPair().getPublic().getEncoded();
        LOGGER.info("PubKey Sntrup: " + ArrayConverter.bytesToHexString(pubKsntrup761));

        byte[] pubKec25519 = ec25519.getLocalKeyPair().getPublic().getEncoded();
        LOGGER.info("PubKey Ec25519: " + ArrayConverter.bytesToHexString(pubKec25519));

        chooser.getContext()
                .getExchangeHashInputHolder()
                .setSntrupX25519ClientPublicKey(
                        ArrayConverter.concatenate(pubKsntrup761, pubKec25519));
        getObject().setEphemeralECPublicKey(pubKec25519, true);
        getObject().setEphemeralSNTRUPPublicKey(pubKsntrup761, true);
    }
}
