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
import de.rub.nds.sshattacker.core.protocol.transport.message.HybridKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.core.protocol.util.KeyExchangeUtil;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HybridKeyExchangeReplyMessagePreparator
        extends SshMessagePreparator<HybridKeyExchangeReplyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public HybridKeyExchangeReplyMessagePreparator(
            Chooser chooser, HybridKeyExchangeReplyMessage message) {
        super(chooser, message, MessageIdConstant.SSH_MSG_HBR_REPLY);
    }

    @Override
    public void prepareMessageSpecificContents() {
        KeyExchangeUtil.prepareHostKeyMessage(chooser.getContext(), getObject());
        prepareHybridPublicValue();
        KeyExchangeUtil.computeSharedSecret(chooser.getContext(), chooser.getHybridKeyExchange());
        KeyExchangeUtil.computeExchangeHash(chooser.getContext());
        KeyExchangeUtil.prepareExchangeHashSignatureMessage(chooser.getContext(), getObject());
        KeyExchangeUtil.setSessionId(chooser.getContext());
        KeyExchangeUtil.generateKeySet(chooser.getContext());
    }

    private void prepareHybridPublicValue() {
        HybridKeyExchange kex = chooser.getHybridKeyExchange();
        AbstractEcdhKeyExchange<?, ?> classical = kex.getClassical();
        classical.generateKeyPair();
        KemKeyExchange postQuantum = kex.getPostQuantum();
        if (postQuantum.getPublicKey() == null) {
            LOGGER.warn(
                    "Post quantum key exchange public key is null, generating new key pair before encapsulation");
            try {
                postQuantum.generateKeyPair();
            } catch (CryptoException e) {
                LOGGER.error(
                        "Error while preparing HybridKeyExchangeReplyMessage - key pair generation failed",
                        e);
            }
        }
        try {
            postQuantum.encapsulate();
        } catch (CryptoException e) {
            LOGGER.warn(
                    "Error while preparing HybridKeyExchangeReplyMessage - encapsulation failed",
                    e);
        }
        byte[] encapsPostQuantum = postQuantum.getEncapsulation();
        getObject().setPostQuantumKeyEncapsulation(encapsPostQuantum);
        byte[] pkClassical = classical.getLocalKeyPair().getPublicKey().getEncoded();
        getObject().setClassicalPublicKey(pkClassical);
        switch (kex.getCombiner()) {
            case CLASSICAL_CONCATENATE_POSTQUANTUM:
                getObject()
                        .setPublicValues(
                                ArrayConverter.concatenate(pkClassical, encapsPostQuantum), true);
                break;
            case POSTQUANTUM_CONCATENATE_CLASSICAL:
                getObject()
                        .setPublicValues(
                                ArrayConverter.concatenate(encapsPostQuantum, pkClassical), true);
                break;
        }
        chooser.getContext()
                .getExchangeHashInputHolder()
                .setHybridClientPublicValues(getObject().getPublicValues().getValue());
    }
}
