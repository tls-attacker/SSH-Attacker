/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.crypto.hash.ExchangeHashInputHolder;
import de.rub.nds.sshattacker.core.crypto.kex.HybridKeyExchange;
import de.rub.nds.sshattacker.core.crypto.kex.KeyAgreement;
import de.rub.nds.sshattacker.core.crypto.kex.KeyEncapsulation;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.HybridKeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.protocol.util.KeyExchangeUtil;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HybridKeyExchangeInitMessagePreparator
        extends SshMessagePreparator<HybridKeyExchangeInitMessage> {
    private static final Logger LOGGER = LogManager.getLogger();

    public HybridKeyExchangeInitMessagePreparator() {
        super(MessageIdConstant.SSH_MSG_HBR_INIT);
    }

    @Override
    public void prepareMessageSpecificContents(
            HybridKeyExchangeInitMessage object, Chooser chooser) {
        HybridKeyExchange keyExchange = chooser.getHybridKeyExchange();
        KeyAgreement agreement = keyExchange.getKeyAgreement();
        KeyEncapsulation encapsulation = keyExchange.getKeyEncapsulation();
        agreement.generateLocalKeyPair();
        encapsulation.generateLocalKeyPair();
        byte[] pubKeyEncapsulation = encapsulation.getLocalKeyPair().getPublicKey().getEncoded();
        byte[] pubKeyAgreement = agreement.getLocalKeyPair().getPublicKey().getEncoded();

        object.setSoftlyAgreementPublicKey(pubKeyAgreement, true, chooser.getConfig());
        object.setSoftlyEncapsulationPublicKey(pubKeyEncapsulation, true, chooser.getConfig());

        ExchangeHashInputHolder inputHolder = chooser.getContext().getExchangeHashInputHolder();
        switch (chooser.getHybridKeyExchange().getCombiner()) {
            case CLASSICAL_CONCATENATE_POSTQUANTUM:
                inputHolder.setHybridClientPublicKey(
                        KeyExchangeUtil.concatenateHybridKeys(
                                pubKeyAgreement, pubKeyEncapsulation));
                break;
            case POSTQUANTUM_CONCATENATE_CLASSICAL:
                inputHolder.setHybridClientPublicKey(
                        KeyExchangeUtil.concatenateHybridKeys(
                                pubKeyEncapsulation, pubKeyAgreement));
                break;
            default:
                LOGGER.warn(
                        "Combiner is not supported, continue without updating ExchangeHashInputHolder");
        }
    }
}
