/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.crypto.hash.ExchangeHashInputHolder;
import de.rub.nds.sshattacker.core.crypto.kex.RsaKeyExchange;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangeSecretMessage;

public class RsaKeyExchangeSecretMessageHandler
        extends SshMessageHandler<RsaKeyExchangeSecretMessage> {

    public RsaKeyExchangeSecretMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void adjustContext(RsaKeyExchangeSecretMessage message) {
        decryptSharedSecret(message);
        updateExchangeHashWithSecrets(message);
    }

    private void decryptSharedSecret(RsaKeyExchangeSecretMessage message) {
        RsaKeyExchange keyExchange = sshContext.getChooser().getRsaKeyExchange();
        try {
            keyExchange.decryptSharedSecret(message.getEncryptedSecret().getValue());
            sshContext.setSharedSecret(keyExchange.getSharedSecret());
        } catch (CryptoException e) {
            LOGGER.warn(
                    "Decryption of shared secret failed, unable to set shared secret in context");
            LOGGER.debug(e);
        }
    }

    private void updateExchangeHashWithSecrets(RsaKeyExchangeSecretMessage message) {
        RsaKeyExchange keyExchange = sshContext.getChooser().getRsaKeyExchange();
        ExchangeHashInputHolder inputHolder = sshContext.getExchangeHashInputHolder();
        inputHolder.setRsaEncryptedSecret(message.getEncryptedSecret().getValue());
        if (keyExchange.isComplete()) {
            inputHolder.setSharedSecret(keyExchange.getSharedSecret());
        } else {
            LOGGER.warn(
                    "Unable to set shared secret in exchange hash, key exchange is still ongoing");
        }
    }
}
