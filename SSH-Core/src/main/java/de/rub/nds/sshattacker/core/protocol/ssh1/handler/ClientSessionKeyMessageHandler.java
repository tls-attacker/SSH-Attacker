/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.crypto.cipher.AbstractCipher;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.ClientSessionKeyMessage;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ClientSessionKeyMessageHandler extends SshMessageHandler<ClientSessionKeyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ClientSessionKeyMessageHandler(SshContext context) {
        super(context);
    }

    /*public HybridKeyExchangeReplyMessageHandler(
            SshContext context, HybridKeyExchangeReplyMessage message) {
        super(context, message);
    }*/

    @Override
    public void adjustContext(ClientSessionKeyMessage message) {
        sshContext.setChosenCipherMethod(message.getChosenCipherMethod());
        sshContext.setChosenProtocolFlags(message.getChosenProtocolFlags());
        byte[] decryptedSessionkey = decryptSessionKey(message);

        sshContext.setSessionKey(decryptedSessionkey);
    }

    private byte[] decryptSessionKey(ClientSessionKeyMessage message) {
        byte[] sessionKey = message.getEncryptedSessioKey().getValue();
        LOGGER.debug("Enc. session Key: {}", ArrayConverter.bytesToHexString(sessionKey));
        if (sessionKey[0] == 0) {
            sessionKey = Arrays.copyOfRange(sessionKey, 1, sessionKey.length);
        }

        CustomRsaPublicKey hostPublickey;
        CustomRsaPublicKey serverPublicKey;

        CustomRsaPrivateKey hostPrivateKey;
        CustomRsaPrivateKey serverPrivatKey;

        SshPublicKey<?, ?> serverkey = sshContext.getServerKey();

        if (serverkey.getPublicKey() instanceof CustomRsaPublicKey) {
            serverPublicKey = (CustomRsaPublicKey) serverkey.getPublicKey();
        } else {
            throw new RuntimeException();
        }

        SshPublicKey<?, ?> hostKey = sshContext.getHostKey().orElseThrow();
        if (hostKey.getPublicKey() instanceof CustomRsaPublicKey) {
            hostPublickey = (CustomRsaPublicKey) hostKey.getPublicKey();
        } else {
            throw new RuntimeException();
        }

        if (!serverkey.getPrivateKey().isPresent()) {
            LOGGER.fatal("ServerPrivateKey not Present");
        }

        if (serverkey.getPrivateKey().isPresent()
                && serverkey.getPrivateKey().get() instanceof CustomRsaPrivateKey) {
            serverPrivatKey = (CustomRsaPrivateKey) serverkey.getPrivateKey().get();
        } else {
            throw new RuntimeException();
        }

        if (hostKey.getPrivateKey().isPresent()
                && hostKey.getPrivateKey().get() instanceof CustomRsaPrivateKey) {
            hostPrivateKey = (CustomRsaPrivateKey) hostKey.getPrivateKey().get();
        } else {
            throw new RuntimeException();
        }

        /*Sanity Check Area*/

        Cipher myCipher = null;
        try {
            byte[] dummy = new byte[] {0, 1, 2, 3};
            byte[] enc_dummy;
            byte[] dec_dummy;
            myCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            myCipher.init(Cipher.ENCRYPT_MODE, hostPublickey);
            enc_dummy = myCipher.doFinal(dummy);

            myCipher.init(Cipher.DECRYPT_MODE, hostPrivateKey);
            dec_dummy = myCipher.doFinal(enc_dummy);

            LOGGER.debug("DUMMY: {} ECN_DUMMY:  {} DEC_DUMMY: {}", dummy, enc_dummy, dec_dummy);

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }

        /*Sanity Check Area*/

        AbstractCipher innerEncryption;
        AbstractCipher outerEncryption;

        if (hostPublickey != null && serverPublicKey != null) {
            try {

                if (hostPublickey.getModulus().bitLength()
                        > serverPublicKey.getModulus().bitLength()) {

                    LOGGER.debug(
                            "Hostkeylenght: {}, ServerKeyLenght: {}",
                            hostPublickey.getModulus().bitLength(),
                            serverPublicKey.getModulus().bitLength());

                    /*                    outerEncryption =
                            CipherFactory.getOaepCipher(
                                    KeyExchangeAlgorithm.RSA1024_PCKS1, hostPrivateKey);
                    sessionKey = outerEncryption.decrypt(sessionKey);

                    innerEncryption =
                            CipherFactory.getOaepCipher(
                                    KeyExchangeAlgorithm.RSA1024_PCKS1, serverPrivatKey);
                    sessionKey = innerEncryption.decrypt(sessionKey);*/

                    /* Alternative Imlementation */

                    Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    encryptCipher.init(Cipher.DECRYPT_MODE, hostPrivateKey);
                    sessionKey = encryptCipher.doFinal(sessionKey);

                    encryptCipher.init(Cipher.DECRYPT_MODE, serverPrivatKey);
                    sessionKey = encryptCipher.doFinal(sessionKey);

                    /* Alternative Imlementation */

                } else {
                    /*
                                        outerEncryption =
                                                CipherFactory.getOaepCipher(
                                                        KeyExchangeAlgorithm.RSA1024_PCKS1, serverPrivatKey);
                                        sessionKey = outerEncryption.decrypt(sessionKey);

                                        innerEncryption =
                                                CipherFactory.getOaepCipher(
                                                        KeyExchangeAlgorithm.RSA1024_PCKS1, hostPrivateKey);
                                        sessionKey = innerEncryption.decrypt(sessionKey);
                    */

                    /* Alternative Imlementation */

                    Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    encryptCipher.init(Cipher.DECRYPT_MODE, serverPrivatKey);
                    sessionKey = encryptCipher.doFinal(sessionKey);

                    encryptCipher.init(Cipher.DECRYPT_MODE, hostPrivateKey);
                    sessionKey = encryptCipher.doFinal(sessionKey);

                    /* Alternative Imlementation */

                }

            } catch (NoSuchPaddingException e) {
                throw new RuntimeException(e);
            } catch (IllegalBlockSizeException e) {
                throw new RuntimeException(e);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            } catch (BadPaddingException e) {
                throw new RuntimeException(e);
            } catch (InvalidKeyException e) {
                throw new RuntimeException(e);
            }
        }

        // Set Sessionkey
        LOGGER.debug("The Session_key is {}", ArrayConverter.bytesToHexString(sessionKey));
        return sessionKey;
    }

    /*private void setRemoteValues(ServerPublicKeyMessage message) {
        sshContext
                .getChooser()
                .getHybridKeyExchange()
                .getKeyAgreement()
                .setRemotePublicKey(message.getPublicKey().getValue());
        LOGGER.info(
                "RemoteKey Agreement = "
                        + ArrayConverter.bytesToRawHexString(message.getPublicKey().getValue()));
        sshContext
                .getChooser()
                .getHybridKeyExchange()
                .getKeyEncapsulation()
                .setEncryptedSharedSecret(message.getCombinedKeyShare().getValue());
        LOGGER.info(
                "Ciphertext Encapsulation = "
                        + ArrayConverter.bytesToRawHexString(
                                message.getCombinedKeyShare().getValue()));
        byte[] combined;
        switch (sshContext.getChooser().getHybridKeyExchange().getCombiner()) {
            case CLASSICAL_CONCATENATE_POSTQUANTUM:
                combined =
                        KeyExchangeUtil.concatenateHybridKeys(
                                message.getPublicKey().getValue(),
                                message.getCombinedKeyShare().getValue());
                sshContext.getExchangeHashInputHolder().setHybridServerPublicKey(combined);
                break;
            case POSTQUANTUM_CONCATENATE_CLASSICAL:
                combined =
                        KeyExchangeUtil.concatenateHybridKeys(
                                message.getCombinedKeyShare().getValue(),
                                message.getPublicKey().getValue());
                sshContext.getExchangeHashInputHolder().setHybridServerPublicKey(combined);
                break;
            default:
                LOGGER.warn(
                        "Combiner"
                                + sshContext.getChooser().getHybridKeyExchange().getCombiner()
                                + " is not supported.");
                break;
        }
    }*/

    /*@Override
    public SshMessageParser<HybridKeyExchangeReplyMessage> getParser(byte[] array) {
        HybridKeyExchange kex = context.getChooser().getHybridKeyExchange();
        return new HybridKeyExchangeReplyMessageParser(
                array, kex.getCombiner(), kex.getPkAgreementLength(), kex.getCiphertextLength());
    }

    @Override
    public SshMessageParser<HybridKeyExchangeReplyMessage> getParser(
            byte[] array, int startPosition) {
        HybridKeyExchange kex = context.getChooser().getHybridKeyExchange();
        return new HybridKeyExchangeReplyMessageParser(
                array,
                startPosition,
                kex.getCombiner(),
                kex.getPkAgreementLength(),
                kex.getCiphertextLength());
    }

    @Override
    public SshMessagePreparator<HybridKeyExchangeReplyMessage> getPreparator() {
        HybridKeyExchange kex = context.getChooser().getHybridKeyExchange();
        return new HybridKeyExchangeReplyMessagePreparator(
                context.getChooser(), message, kex.getCombiner());
    }

    @Override
    public SshMessageSerializer<HybridKeyExchangeReplyMessage> getSerializer() {
        HybridKeyExchange kex = context.getChooser().getHybridKeyExchange();
        return new HybridKeyExchangeReplyMessageSerializer(message, kex.getCombiner());
    }*/
}
