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

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class RsaKeyExchangeSecretMessagePreparator extends SshMessagePreparator<RsaKeyExchangeSecretMessage> {
    public RsaKeyExchangeSecretMessagePreparator(Chooser chooser, RsaKeyExchangeSecretMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        RsaKeyExchangeSecretMessage message = getObject();
        message.setMessageID(MessageIDConstant.SSH_MSG_KEXRSA_SECRET);

        if(chooser.getContext().getKeyExchangeInstance().isPresent() && chooser.getContext().getKeyExchangeAlgorithm().isPresent()) {
            KeyExchange keyExchange = chooser.getContext().getKeyExchangeInstance().get();
            KeyExchangeAlgorithm keyExchangeAlg = chooser.getContext().getKeyExchangeAlgorithm().get();

            if(keyExchange instanceof RsaKeyExchange) {
                keyExchange.computeSharedSecret();
                message.setSecret(keyExchange.getSharedSecret().toByteArray(), true);
                // Note: data to be encrypted consists of length field + secret (see RFC 4432)
                byte[] encryptedSecret = prepareEncryptedSecret(prepareData(message), keyExchangeAlg, (RsaKeyExchange) keyExchange);

                message.setEncryptedSecret(encryptedSecret, true);
                updateExchangeHashWithSecrets(message);

            } else {
                raisePreparationException("Cannot prepare secret message, " +
                        "key exchange instance is not RSA, but: " + keyExchange.getClass());
            }
        } else {
            raisePreparationException("Cannot prepare secret message, key exchange instance or algorithm is missing.");
        }
    }

    private byte[] prepareData(RsaKeyExchangeSecretMessage message) {
        ByteArrayOutputStream dataStream = new ByteArrayOutputStream();
        try {
            dataStream.write(message.getSecretLength().getByteArray(DataFormatConstants.MPINT_SIZE_LENGTH));
            dataStream.write(message.getSecret().getValue());
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

    private void updateExchangeHashWithSecrets(RsaKeyExchangeSecretMessage message) {
        ExchangeHash exchangeHash = chooser.getContext().getExchangeHashInstance();

        if (exchangeHash instanceof RsaExchangeHash) {
            RsaExchangeHash rsaExchangeHash = (RsaExchangeHash) exchangeHash;
            rsaExchangeHash.setEncryptedSecret(message.getEncryptedSecret().getValue());
            rsaExchangeHash.setSharedSecret(message.getSecret().getValue());
        } else {
            raisePreparationException("Cannot prepare secret message, " +
                    "exchange hash instance is not RSA, instead: " + exchangeHash.getClass());
        }
    }
}
