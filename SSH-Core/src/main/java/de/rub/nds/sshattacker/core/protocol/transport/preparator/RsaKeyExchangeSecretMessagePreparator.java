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
import de.rub.nds.sshattacker.core.crypto.kex.KeyExchange;
import de.rub.nds.sshattacker.core.crypto.kex.RsaKeyExchange;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangeSecretMessage;
import de.rub.nds.sshattacker.core.util.RsaPublicKey;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource.PSpecified;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.MGF1ParameterSpec;

public class RsaKeyExchangeSecretMessagePreparator extends SshMessagePreparator<RsaKeyExchangeSecretMessage> {
//TODO: Make this class look better, create Cipher class for performing encryption etc.
    public RsaKeyExchangeSecretMessagePreparator(Chooser chooser, RsaKeyExchangeSecretMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setMessageID(MessageIDConstant.SSH_MSG_KEXRSA_SECRET);
        if(chooser.getContext().getKeyExchangeInstance().isPresent() && chooser.getContext().getKeyExchangeAlgorithm().isPresent()) {
            KeyExchange keyExchange = chooser.getContext().getKeyExchangeInstance().get();
            KeyExchangeAlgorithm keyExchangeAlg = chooser.getContext().getKeyExchangeAlgorithm().get();

            if(keyExchange instanceof RsaKeyExchange) {
                keyExchange.computeSharedSecret();
                //BigInteger sharedSecret = keyExchange.getSharedSecret();
                BigInteger sharedSecret = BigInteger.valueOf(1);
                getObject().setSecret(sharedSecret.toByteArray(), true);

                ByteArrayOutputStream dataStream = new ByteArrayOutputStream();
                try {
                    dataStream.write(getObject().getSecretLength().getByteArray(DataFormatConstants.MPINT_SIZE_LENGTH));
                    dataStream.write(getObject().getSecret().getValue());
                } catch (IOException e) {
                    raisePreparationException("Secret could not be converted to bytes. Error: " + e.getMessage());
                }

                byte[] data = dataStream.toByteArray();

                byte[] encryptedSecret = new byte[0];

                try {
                    encryptedSecret = performEncryption(keyExchangeAlg, (RsaKeyExchange) keyExchange, data);
                } catch (CryptoException e) {
                    raisePreparationException(e.getMessage());
                }
                getObject().setEncryptedSecret(encryptedSecret, true);

            } else {
                raisePreparationException("Cannot prepare secret message, " +
                        "key exchange instance is not RSA, instead: " + keyExchange);
            }
        } else {
            raisePreparationException("Cannot prepare secret message, key exchange instance or algorithm is missing");
        }
    }

    private byte[] performEncryption(KeyExchangeAlgorithm keyExchangeAlgorithm, RsaKeyExchange keyExchange, byte[] data) throws CryptoException {
        Cipher cipher;
        try {
            switch (keyExchangeAlgorithm) {
                case RSA1024_SHA1:
                    cipher = prepareCipher("RSA/ECB/OAEPWithSHA-1AndMGF1Padding", "SHA-1", keyExchange.getPublicKey());
                    return cipher.doFinal(data);
                case RSA2048_SHA256:
                    cipher = prepareCipher("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "SHA-256", keyExchange.getPublicKey());
                    return cipher.doFinal(data);
                default:
                    raisePreparationException("Key exchange algorithm is not RSA but: " + keyExchangeAlgorithm);
            }
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new CryptoException("Encryption of secret with RSAES-OAEP failed: " + e);
        }
        return new byte[0];
    }

    private Cipher prepareCipher(String instanceName, String hashFunction, RsaPublicKey rsaPublicKey) throws CryptoException {
        try {
            Cipher cipher;
            cipher = Cipher.getInstance(instanceName);
            OAEPParameterSpec spec = new OAEPParameterSpec(hashFunction, "MGF1",
                    new MGF1ParameterSpec(hashFunction), PSpecified.DEFAULT);
            cipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey, spec);
            return cipher;
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new CryptoException("RSA Cipher creation failed: " + e);
        }
    }
}
