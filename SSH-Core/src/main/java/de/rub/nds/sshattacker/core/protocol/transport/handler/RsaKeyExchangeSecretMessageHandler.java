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
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangeSecretMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.RsaKeyExchangeSecretMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.RsaKeyExchangeSecretMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.RsaKeyExchangeSecretMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class RsaKeyExchangeSecretMessageHandler
        extends SshMessageHandler<RsaKeyExchangeSecretMessage> {

    public RsaKeyExchangeSecretMessageHandler(SshContext context) {
        super(context);
    }

    public RsaKeyExchangeSecretMessageHandler(
            SshContext context, RsaKeyExchangeSecretMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        decryptSharedSecret();
        updateExchangeHashWithSecrets();
    }

    private void decryptSharedSecret() {
        RsaKeyExchange keyExchange = context.getChooser().getRsaKeyExchange();
        try {
            keyExchange.decryptSharedSecret(message.getEncryptedSecret().getValue());
            context.setSharedSecret(keyExchange.getSharedSecret());
        } catch (CryptoException e) {
            LOGGER.warn(
                    "Decryption of shared secret failed, unable to set shared secret in context");
            LOGGER.debug(e);
        }
    }

    private void updateExchangeHashWithSecrets() {
        RsaKeyExchange keyExchange = context.getChooser().getRsaKeyExchange();
        ExchangeHashInputHolder inputHolder = context.getExchangeHashInputHolder();
        inputHolder.setRsaEncryptedSecret(message.getEncryptedSecret().getValue());
        if (keyExchange.isComplete()) {
            inputHolder.setSharedSecret(keyExchange.getSharedSecret());
        } else {
            LOGGER.warn(
                    "Unable to set shared secret in exchange hash, key exchange is still ongoing");
        }
    }

    @Override
    public RsaKeyExchangeSecretMessageParser getParser(byte[] array) {
        return new RsaKeyExchangeSecretMessageParser(array);
    }

    @Override
    public RsaKeyExchangeSecretMessageParser getParser(byte[] array, int startPosition) {
        return new RsaKeyExchangeSecretMessageParser(array, startPosition);
    }

    public static final RsaKeyExchangeSecretMessagePreparator PREPARATOR =
            new RsaKeyExchangeSecretMessagePreparator();

    public static final RsaKeyExchangeSecretMessageSerializer SERIALIZER =
            new RsaKeyExchangeSecretMessageSerializer();
}
