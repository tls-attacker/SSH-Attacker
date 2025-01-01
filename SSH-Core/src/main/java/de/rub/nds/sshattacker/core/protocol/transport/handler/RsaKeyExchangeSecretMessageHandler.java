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

    @Override
    public void adjustContext(SshContext context, RsaKeyExchangeSecretMessage object) {
        decryptSharedSecret(context, object);
        updateExchangeHashWithSecrets(context, object);
    }

    private static void decryptSharedSecret(
            SshContext context, RsaKeyExchangeSecretMessage object) {
        RsaKeyExchange keyExchange = context.getChooser().getRsaKeyExchange();
        try {
            keyExchange.decryptSharedSecret(object.getEncryptedSecret().getValue());
            context.setSharedSecret(keyExchange.getSharedSecret());
        } catch (CryptoException e) {
            LOGGER.warn(
                    "Decryption of shared secret failed, unable to set shared secret in context");
            LOGGER.debug(e);
        }
    }

    private static void updateExchangeHashWithSecrets(
            SshContext context, RsaKeyExchangeSecretMessage object) {
        RsaKeyExchange keyExchange = context.getChooser().getRsaKeyExchange();
        ExchangeHashInputHolder inputHolder = context.getExchangeHashInputHolder();
        inputHolder.setRsaEncryptedSecret(object.getEncryptedSecret().getValue());
        if (keyExchange.isComplete()) {
            inputHolder.setSharedSecret(keyExchange.getSharedSecret());
        } else {
            LOGGER.warn(
                    "Unable to set shared secret in exchange hash, key exchange is still ongoing");
        }
    }

    @Override
    public RsaKeyExchangeSecretMessageParser getParser(byte[] array, SshContext context) {
        return new RsaKeyExchangeSecretMessageParser(array);
    }

    @Override
    public RsaKeyExchangeSecretMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new RsaKeyExchangeSecretMessageParser(array, startPosition);
    }

    public static final RsaKeyExchangeSecretMessagePreparator PREPARATOR =
            new RsaKeyExchangeSecretMessagePreparator();

    public static final RsaKeyExchangeSecretMessageSerializer SERIALIZER =
            new RsaKeyExchangeSecretMessageSerializer();
}
