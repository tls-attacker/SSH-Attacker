/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.crypto.kex.RsaKeyExchange;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPublicKey;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangePubkeyMessage;
import de.rub.nds.sshattacker.core.protocol.util.KeyExchangeUtil;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RsaKeyExchangePubkeyMessagePreparator
        extends SshMessagePreparator<RsaKeyExchangePubkeyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public RsaKeyExchangePubkeyMessagePreparator() {
        super(MessageIdConstant.SSH_MSG_KEXRSA_PUBKEY);
    }

    @Override
    public void prepareMessageSpecificContents(
            RsaKeyExchangePubkeyMessage object, Chooser chooser) {
        KeyExchangeUtil.prepareHostKeyMessage(chooser.getContext(), object);
        prepareTransientPublicKey(object, chooser);
    }

    private static void prepareTransientPublicKey(
            RsaKeyExchangePubkeyMessage object, Chooser chooser) {

        try {
            RsaKeyExchange keyExchange = chooser.getRsaKeyExchange();
            keyExchange.generateKeyPair();
            CustomRsaPublicKey transientKey = (CustomRsaPublicKey) keyExchange.getPublicKey();

            object.setTransientPublicKeyBytes(transientKey.serialize(), true);

            chooser.getContext()
                    .getExchangeHashInputHolder()
                    .setRsaTransientKey(object.getTransientPublicKey());
        } catch (CryptoException e) {
            // This branch should never be reached as this would indicate an RSA key generation
            // failure
            LOGGER.warn(
                    "Transient public key preparation failed - workflow will continue but transient public key will be left empty");
            LOGGER.debug(e);
            object.setTransientPublicKeyBytes(new byte[0], true);
            // Using fallback transient key for ExchangeHashInputHolder
            chooser.getContext()
                    .getExchangeHashInputHolder()
                    .setRsaTransientKey(chooser.getConfig().getFallbackRsaTransientPublicKey());
        }
    }
}
