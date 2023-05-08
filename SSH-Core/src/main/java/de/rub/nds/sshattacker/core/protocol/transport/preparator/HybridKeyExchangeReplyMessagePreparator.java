/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.HybridKeyExchangeCombiner;
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.crypto.hash.ExchangeHashInputHolder;
import de.rub.nds.sshattacker.core.crypto.kex.HybridKeyExchange;
import de.rub.nds.sshattacker.core.crypto.kex.KeyAgreement;
import de.rub.nds.sshattacker.core.crypto.kex.KeyEncapsulation;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.HybridKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.core.protocol.util.KeyExchangeUtil;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HybridKeyExchangeReplyMessagePreparator
        extends SshMessagePreparator<HybridKeyExchangeReplyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();
    private final HybridKeyExchangeCombiner combiner;

    public HybridKeyExchangeReplyMessagePreparator(
            Chooser chooser,
            HybridKeyExchangeReplyMessage message,
            HybridKeyExchangeCombiner combiner) {
        super(chooser, message, MessageIdConstant.SSH_MSG_HBR_REPLY);
        this.combiner = combiner;
    }

    @Override
    public void prepareMessageSpecificContents() {
        KeyExchangeUtil.prepareHostKeyMessage(chooser.getContext(), getObject());
        prepareHybridKey();
        chooser.getHybridKeyExchange().combineSharedSecrets();
        chooser.getContext().setSharedSecret(chooser.getHybridKeyExchange().getSharedSecret());
        chooser.getContext()
                .getExchangeHashInputHolder()
                .setSharedSecret(chooser.getHybridKeyExchange().getSharedSecret());
        KeyExchangeUtil.computeExchangeHash(chooser.getContext());
        KeyExchangeUtil.prepareExchangeHashSignatureMessage(chooser.getContext(), getObject());
        KeyExchangeUtil.setSessionId(chooser.getContext());
        KeyExchangeUtil.generateKeySet(chooser.getContext());
    }

    private void prepareHybridKey() {
        HybridKeyExchange keyExchange = chooser.getHybridKeyExchange();
        KeyAgreement agreement = keyExchange.getKeyAgreement();
        KeyEncapsulation encapsulation = keyExchange.getKeyEncapsulation();
        agreement.generateLocalKeyPair();
        encapsulation.encryptSharedSecret();

        ExchangeHashInputHolder inputHolder = chooser.getContext().getExchangeHashInputHolder();
        byte[] agreementBytes = agreement.getLocalKeyPair().getPublic().getEncoded();
        byte[] encapsulationBytes = encapsulation.getEncryptedSharedSecret();
        getObject().setPublicKey(agreementBytes, true);
        getObject().setCiphertext(encapsulationBytes, true);
        byte[] concatenated;
        switch (combiner) {
            case CLASSICAL_CONCATENATE_POSTQUANTUM:
                concatenated =
                        KeyExchangeUtil.concatenateHybridKeys(agreementBytes, encapsulationBytes);
                inputHolder.setHybridServerPublicKey(concatenated);
                break;
            case POSTQUANTUM_CONCATENATE_CLASSICAL:
                concatenated =
                        KeyExchangeUtil.concatenateHybridKeys(encapsulationBytes, agreementBytes);
                inputHolder.setHybridServerPublicKey(concatenated);
                break;
            default:
                LOGGER.warn("combiner is not supported. Can not set Hybrid Key.");
                break;
        }
    }
}
