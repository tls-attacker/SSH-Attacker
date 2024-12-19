/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.crypto.kex.RsaKeyExchange;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.crypto.util.PublicKeyHelper;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.exceptions.ParserException;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangePubkeyMessage;
import de.rub.nds.sshattacker.core.protocol.util.KeyExchangeUtil;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RsaKeyExchangePubkeyMessagePreparator
        extends SshMessagePreparator<RsaKeyExchangePubkeyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public RsaKeyExchangePubkeyMessagePreparator(
            Chooser chooser, RsaKeyExchangePubkeyMessage message) {
        super(chooser, message, MessageIdConstant.SSH_MSG_KEXRSA_PUBKEY);
    }

    @Override
    public void prepareMessageSpecificContents() {
        KeyExchangeUtil.prepareHostKeyMessage(chooser.getContext(), getObject());
        prepareTransientPublicKey();
    }

    private void prepareTransientPublicKey() {
        RsaKeyExchangePubkeyMessage message = getObject();
        Config config = chooser.getConfig();
        try {
            RsaKeyExchange keyExchange = chooser.getRsaKeyExchange();
            keyExchange.generateTransientKey();
            SshPublicKey<CustomRsaPublicKey, CustomRsaPrivateKey> transientKey =
                    keyExchange.getTransientKey();

            message.setSoftlyTransientPublicKeyBytes(
                    PublicKeyHelper.encode(transientKey), true, config);

            chooser.getContext().getExchangeHashInputHolder().setRsaTransientKey(transientKey);
        } catch (CryptoException | IllegalArgumentException | ParserException e) {
            // This branch should never be reached as this would indicate an RSA key generation
            // failure
            LOGGER.warn(
                    "Transient public key preparation failed - workflow will continue but transient public key will be left empty");
            LOGGER.debug(e);
            message.setSoftlyTransientPublicKeyBytes(new byte[0], true, config);
            // Using fallback transient key for ExchangeHashInputHolder
            chooser.getContext()
                    .getExchangeHashInputHolder()
                    .setRsaTransientKey(config.getFallbackRsaTransientPublicKey());
        }
    }
}
