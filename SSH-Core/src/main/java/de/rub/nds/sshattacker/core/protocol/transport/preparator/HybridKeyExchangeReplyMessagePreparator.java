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
        KeyExchangeUtil.computeSharedSecret(chooser.getContext(), chooser.getHybridKeyExchange());
        KeyExchangeUtil.computeExchangeHash(context);
        KeyExchangeUtil.prepareExchangeHashSignatureMessage(context, object);
        KeyExchangeUtil.setSessionId(context);
        KeyExchangeUtil.generateKeySet(context);
    }

    private static void prepareHybridKey(HybridKeyExchangeReplyMessage object, Chooser chooser) {
        HybridKeyExchange keyExchange = chooser.getHybridKeyExchange();
        AbstractEcdhKeyExchange<?, ?> classical = keyExchange.getClassical();
        classical.generateKeyPair();
        KemKeyExchange postQuantum = keyExchange.getPostQuantum();
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

        byte[] pkClassical = classical.getLocalKeyPair().getPublicKey().getEncoded();
        byte[] encapsPostQuantum = postQuantum.getEncapsulation();

        byte[] keys = null;
        switch (chooser.getHybridKeyExchange().getCombiner()) {
            case CLASSICAL_CONCATENATE_POSTQUANTUM:
                keys = ArrayConverter.concatenate(pkClassical, encapsPostQuantum);
                break;
            case POSTQUANTUM_CONCATENATE_CLASSICAL:
                keys = ArrayConverter.concatenate(encapsPostQuantum, pkClassical);
                break;
            default:
                LOGGER.warn("Combiner is not supported. Can not set Hybrid Key.");
                break;
        }
        object.setSoftlyConcatenatedHybridKeys(keys, true, chooser.getConfig());
    }
}
