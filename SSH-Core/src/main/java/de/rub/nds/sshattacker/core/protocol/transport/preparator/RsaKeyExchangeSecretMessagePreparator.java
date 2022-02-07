/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.crypto.cipher.RsaCipher;
import de.rub.nds.sshattacker.core.crypto.hash.ExchangeHash;
import de.rub.nds.sshattacker.core.crypto.hash.RsaExchangeHash;
import de.rub.nds.sshattacker.core.crypto.kex.KeyExchange;
import de.rub.nds.sshattacker.core.crypto.kex.RsaKeyExchange;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangeSecretMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

public class RsaKeyExchangeSecretMessagePreparator extends SshMessagePreparator<RsaKeyExchangeSecretMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public RsaKeyExchangeSecretMessagePreparator(Chooser chooser, RsaKeyExchangeSecretMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        RsaKeyExchangeSecretMessage message = getObject();
        message.setMessageID(MessageIDConstant.SSH_MSG_KEXRSA_SECRET);
        RsaKeyExchange keyExchange = chooser.getRsaKeyExchange();
        KeyExchangeAlgorithm keyExchangeAlg;
        if (chooser.getContext().getKeyExchangeAlgorithm().isPresent()) {
            keyExchangeAlg = chooser.getContext().getKeyExchangeAlgorithm().get();
        } else {
            keyExchangeAlg = chooser.getConfig().getDefaultRsaKeyExchangeAlgorithm();
        }

        keyExchange.computeSharedSecret();
        LOGGER.debug("Shared secret: " + keyExchange.getSharedSecret());
        // Note: data to be encrypted consists of length field + secret (see RFC 4432)
        byte[] encryptedSecret = prepareEncryptedSecret(prepareData(keyExchange), keyExchangeAlg, keyExchange);

        message.setEncryptedSecret(encryptedSecret, true);
        updateExchangeHashWithSecrets(message, keyExchange);
    }

    private byte[] prepareData(RsaKeyExchange keyExchange) {
        ByteArrayOutputStream dataStream = new ByteArrayOutputStream();
        try {
            byte[] secret = keyExchange.getSharedSecret().toByteArray();
            byte[] secretLength = ByteBuffer.allocate(DataFormatConstants.MPINT_SIZE_LENGTH).putInt(secret.length).array();
            dataStream.write(secretLength);
            dataStream.write(secret);
        } catch (IOException e) {
            raisePreparationException("Secret could not be converted to bytes. Error: " + e.getMessage());
        }
        return dataStream.toByteArray();
    }
    
    private byte[] prepareEncryptedSecret(byte[] secret, KeyExchangeAlgorithm keyExchangeAlg, RsaKeyExchange keyExchange) {
        RsaCipher rsaCipher = new RsaCipher(keyExchangeAlg, keyExchange.getPublicKey());
        try {
            return rsaCipher.encrypt(secret);
        } catch (CryptoException e) {
            raisePreparationException(e.getMessage());
            return new byte[0];
        }
    }

    private void updateExchangeHashWithSecrets(RsaKeyExchangeSecretMessage message, RsaKeyExchange keyExchange) {
        ExchangeHash exchangeHash = chooser.getContext().getExchangeHashInstance();

        RsaExchangeHash rsaExchangeHash;
        if (exchangeHash instanceof RsaExchangeHash) {
            rsaExchangeHash = (RsaExchangeHash) exchangeHash;
        } else {
            rsaExchangeHash = RsaExchangeHash.from(exchangeHash);
        }
        rsaExchangeHash.setEncryptedSecret(message.getEncryptedSecret().getValue());
        rsaExchangeHash.setSharedSecret(keyExchange.getSharedSecret());
    }
}
