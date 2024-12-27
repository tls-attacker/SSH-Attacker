/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.crypto.kex.HybridKeyExchange;
import de.rub.nds.sshattacker.core.crypto.kex.KeyAgreement;
import de.rub.nds.sshattacker.core.crypto.kex.KeyEncapsulation;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.HybridKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.core.protocol.util.KeyExchangeUtil;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HybridKeyExchangeReplyMessagePreparator
        extends SshMessagePreparator<HybridKeyExchangeReplyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public HybridKeyExchangeReplyMessagePreparator() {
        super(MessageIdConstant.SSH_MSG_HBR_REPLY);
    }

    @Override
    public void prepareMessageSpecificContents(
            HybridKeyExchangeReplyMessage object, Chooser chooser) {
        SshContext context = chooser.getContext();
        KeyExchangeUtil.prepareHostKeyMessage(context, object);
        prepareHybridKey(object, chooser);
        chooser.getHybridKeyExchange().combineSharedSecrets();
        context.setSharedSecret(chooser.getHybridKeyExchange().getSharedSecret());
        context.getExchangeHashInputHolder()
                .setSharedSecret(chooser.getHybridKeyExchange().getSharedSecret());
        KeyExchangeUtil.computeExchangeHash(context);
        KeyExchangeUtil.prepareExchangeHashSignatureMessage(context, object);
        KeyExchangeUtil.setSessionId(context);
        KeyExchangeUtil.generateKeySet(context);
    }

    private static void prepareHybridKey(HybridKeyExchangeReplyMessage object, Chooser chooser) {
        HybridKeyExchange keyExchange = chooser.getHybridKeyExchange();
        KeyAgreement agreement = keyExchange.getKeyAgreement();
        KeyEncapsulation encapsulation = keyExchange.getKeyEncapsulation();
        agreement.generateLocalKeyPair();
        encapsulation.encryptSharedSecret();
        byte[] agreementBytes = agreement.getLocalKeyPair().getPublicKey().getEncoded();
        byte[] encapsulationBytes = encapsulation.getEncryptedSharedSecret();

        byte[] keys = null;
        switch (chooser.getHybridKeyExchange().getCombiner()) {
            case CLASSICAL_CONCATENATE_POSTQUANTUM:
                keys = KeyExchangeUtil.concatenateHybridKeys(agreementBytes, encapsulationBytes);
                break;
            case POSTQUANTUM_CONCATENATE_CLASSICAL:
                keys = KeyExchangeUtil.concatenateHybridKeys(encapsulationBytes, agreementBytes);
                break;
            default:
                LOGGER.warn("Combiner is not supported. Can not set Hybrid Key.");
                break;
        }
        object.setSoftlyConcatenatedHybridKeys(keys, true, chooser.getConfig());
    }
}
