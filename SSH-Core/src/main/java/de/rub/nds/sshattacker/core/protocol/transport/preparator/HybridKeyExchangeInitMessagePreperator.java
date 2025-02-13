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
import de.rub.nds.sshattacker.core.crypto.kex.*;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.HybridKeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HybridKeyExchangeInitMessagePreperator
        extends SshMessagePreparator<HybridKeyExchangeInitMessage> {
    private static final Logger LOGGER = LogManager.getLogger();

    public HybridKeyExchangeInitMessagePreperator(
            Chooser chooser, HybridKeyExchangeInitMessage message) {
        super(chooser, message, MessageIdConstant.SSH_MSG_HBR_INIT);
    }

    @Override
    public void prepareMessageSpecificContents() {
        prepareHybridPublicValue();
    }

    private void prepareHybridPublicValue() {
        HybridKeyExchange kex = chooser.getHybridKeyExchange();
        AbstractEcdhKeyExchange<?, ?> classical = kex.getClassical();
        KemKeyExchange postQuantum = kex.getPostQuantum();
        try {
            classical.generateKeyPair();
            postQuantum.generateKeyPair();
        } catch (CryptoException e) {
            LOGGER.error(
                    "Error while preparing HybridKeyExchangeInitMessage - key pair generation failed",
                    e);
        }
        byte[] pkPostQuantum = postQuantum.getPublicKeyBytes();
        getObject().setPostQuantumPublicKey(pkPostQuantum);
        LOGGER.debug("Post quantum public key: {}", ArrayConverter.bytesToHexString(pkPostQuantum));
        byte[] pkClassical = classical.getLocalKeyPair().getPublicKey().getEncoded();
        getObject().setClassicalPublicKey(pkClassical);
        LOGGER.debug("Classical public key: {}", ArrayConverter.bytesToHexString(pkClassical));
        switch (kex.getCombiner()) {
            case CLASSICAL_CONCATENATE_POSTQUANTUM:
                getObject()
                        .setPublicValues(
                                ArrayConverter.concatenate(pkClassical, pkPostQuantum), true);
                break;
            case POSTQUANTUM_CONCATENATE_CLASSICAL:
                getObject()
                        .setPublicValues(
                                ArrayConverter.concatenate(pkPostQuantum, pkClassical), true);
                break;
        }
        chooser.getContext()
                .getExchangeHashInputHolder()
                .setHybridClientPublicValues(getObject().getPublicValues().getValue());
    }
}
