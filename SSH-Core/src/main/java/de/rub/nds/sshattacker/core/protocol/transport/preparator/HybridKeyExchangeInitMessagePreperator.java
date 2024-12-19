/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.constants.HybridKeyExchangeCombiner;
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

public class HybridKeyExchangeInitMessagePreperator
        extends SshMessagePreparator<HybridKeyExchangeInitMessage> {
    private static final Logger LOGGER = LogManager.getLogger();
    private final HybridKeyExchangeCombiner combiner;

    public HybridKeyExchangeInitMessagePreperator(
            Chooser chooser,
            HybridKeyExchangeInitMessage message,
            HybridKeyExchangeCombiner combiner) {
        super(chooser, message, MessageIdConstant.SSH_MSG_HBR_INIT);
        this.combiner = combiner;
    }

    @Override
    public void prepareMessageSpecificContents() {
        HybridKeyExchange keyExchange = chooser.getHybridKeyExchange();
        KeyAgreement agreement = keyExchange.getKeyAgreement();
        KeyEncapsulation encapsulation = keyExchange.getKeyEncapsulation();
        agreement.generateLocalKeyPair();
        encapsulation.generateLocalKeyPair();
        byte[] pubKeyEncapsulation = encapsulation.getLocalKeyPair().getPublicKey().getEncoded();
        byte[] pubKeyAgreement = agreement.getLocalKeyPair().getPublicKey().getEncoded();

        HybridKeyExchangeInitMessage message = getObject();
        Config config = chooser.getConfig();
        message.setSoftlyAgreementPublicKey(pubKeyAgreement, true, config);
        message.setSoftlyEncapsulationPublicKey(pubKeyEncapsulation, true, config);

        ExchangeHashInputHolder inputHolder = chooser.getContext().getExchangeHashInputHolder();
        switch (combiner) {
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
                        "Unsupported combiner {}, continue without updating ExchangeHashInputHolder",
                        combiner);
        }
    }
}
