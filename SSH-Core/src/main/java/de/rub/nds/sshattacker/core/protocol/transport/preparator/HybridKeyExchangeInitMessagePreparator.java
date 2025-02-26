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
        AbstractEcdhKeyExchange<?, ?> classical = keyExchange.getClassical();
        KemKeyExchange postQuantum = keyExchange.getPostQuantum();
        try {
            classical.generateKeyPair();
            postQuantum.generateKeyPair();
        } catch (CryptoException e) {
            LOGGER.error(
                    "Error while preparing HybridKeyExchangeInitMessage - key pair generation failed",
                    e);
        }

        byte[] pkPostQuantum = postQuantum.getPublicKeyBytes();
        byte[] pkClassical = classical.getLocalKeyPair().getPublicKey().getEncoded();

        byte[] keys;
        switch (chooser.getHybridKeyExchange().getCombiner()) {
            case CLASSICAL_CONCATENATE_POSTQUANTUM:
                keys = ArrayConverter.concatenate(pkClassical, pkPostQuantum);
                break;
            case POSTQUANTUM_CONCATENATE_CLASSICAL:
                keys = ArrayConverter.concatenate(pkPostQuantum, pkClassical);
                break;
            default:
                keys = new byte[0];
                LOGGER.warn(
                        "Combiner is not supported, continue without updating ExchangeHashInputHolder");
        }
        object.setConcatenatedHybridKeys(keys, true);
    }
}
