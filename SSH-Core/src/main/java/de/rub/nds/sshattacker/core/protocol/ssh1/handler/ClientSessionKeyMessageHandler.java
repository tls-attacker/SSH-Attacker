/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.handler;

import static de.rub.nds.sshattacker.core.constants.CipherMethod.*;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.CipherMethod;
import de.rub.nds.sshattacker.core.constants.CipherMode;
import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithm;
import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithmType;
import de.rub.nds.sshattacker.core.crypto.cipher.AbstractCipher;
import de.rub.nds.sshattacker.core.crypto.cipher.CipherFactory;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.packet.cipher.PacketCipher;
import de.rub.nds.sshattacker.core.packet.cipher.PacketCipherFactory;
import de.rub.nds.sshattacker.core.packet.cipher.keys.AbstractKeySet;
import de.rub.nds.sshattacker.core.protocol.common.MessageSentHandler;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.ClientSessionKeyMessage;
import de.rub.nds.sshattacker.core.protocol.util.KeyExchangeUtil;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;
import javax.crypto.BadPaddingException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ClientSessionKeyMessageHandler extends SshMessageHandler<ClientSessionKeyMessage>
        implements MessageSentHandler {

    private static final Logger LOGGER = LogManager.getLogger();

    public ClientSessionKeyMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void adjustContext(ClientSessionKeyMessage message) {
        sshContext.setChosenCipherMethod(message.getChosenCipherMethod());
        sshContext.setChosenProtocolFlags(message.getChosenProtocolFlags());
        Chooser chooser = sshContext.getChooser();

        EncryptionAlgorithm encryptionAlgorithm;

        CipherMethod chosenCipherMethod = sshContext.getChosenCipherMethod();

        switch (chosenCipherMethod) {
            case SSH_CIPHER_3DES:
                encryptionAlgorithm = EncryptionAlgorithm.TRIPLE_DES_CBC;
                break;
            case SSH_CIPHER_NONE:
                encryptionAlgorithm = EncryptionAlgorithm.NONE;
                break;
            case SSH_CIPHER_IDEA:
                encryptionAlgorithm = EncryptionAlgorithm.IDEA_CTR; // Wrong, needts to be IDEA_CFB!
                break;
            case SSH_CIPHER_DES:
                encryptionAlgorithm = EncryptionAlgorithm.DES_CBC;
                break;
            case SSH_CIPHER_ARCFOUR:
                encryptionAlgorithm = EncryptionAlgorithm.ARCFOUR;
                break;
            case SSH_CIPHER_BLOWFISH:
                encryptionAlgorithm = EncryptionAlgorithm.BLOWFISH_CBC;
                break;
            default:
                encryptionAlgorithm = EncryptionAlgorithm.NONE;
                // Fallback to None if nothing applied, throw Warning.
                LOGGER.warn(
                        "chosen unsupported Encryption-Algorithm {}, fall back to NONE",
                        chosenCipherMethod);
        }
        LOGGER.info("Successfulle applied Encryption Algorihm {}", encryptionAlgorithm);

        // Set Server2Client and Client2Server identical because of SSH1
        chooser.getContext()
                .getSshContext()
                .setEncryptionAlgorithmClientToServer(encryptionAlgorithm);

        chooser.getContext()
                .getSshContext()
                .setEncryptionAlgorithmServerToClient(encryptionAlgorithm);

        byte[] decryptedSessionkey;
        try {
            decryptedSessionkey = decryptSessionKey(message);
        } catch (CryptoException e) {
            throw new RuntimeException(e);
        }

        sshContext.setSessionKey(decryptedSessionkey);
        sshContext.setSharedSecret(decryptedSessionkey);
        KeyExchangeUtil.generateKeySet(sshContext);

        Optional<AbstractKeySet> keySet = sshContext.getKeySet();

        // We Recive here, because we are in the handler
        encryptionAlgorithm = chooser.getReceiveEncryptionAlgorithm();
        AbstractKeySet activeKeySet = sshContext.getPacketLayer().getDecryptorCipher().getKeySet();
        EncryptionAlgorithm activeEncryptionAlgorithm =
                sshContext.getPacketLayer().getDecryptorCipher().getEncryptionAlgorithm();

        if (!sshContext.getConfig().getForcePacketCipherChange()
                && Objects.equals(activeKeySet, keySet.get())
                && encryptionAlgorithm == activeEncryptionAlgorithm
                && (encryptionAlgorithm.getType() == EncryptionAlgorithmType.AEAD)) {
            LOGGER.info(
                    "Key set and algorithms unchanged, not changing active decryption cipher - workflow will continue with old cipher");
            return;
        }

        try {
            PacketCipher packetCipher =
                    PacketCipherFactory.getPacketCipher(
                            sshContext,
                            keySet.get(),
                            encryptionAlgorithm,
                            null,
                            CipherMode.DECRYPT);
            sshContext.getPacketLayer().updateDecryptionCipher(packetCipher);

        } catch (IllegalArgumentException e) {
            LOGGER.warn(
                    "Caught an exception while trying to update the active {} cipher after handling a new keys message - workflow will continue with old cipher",
                    "decryption");
            LOGGER.debug(e);
        }

        try {
            PacketCipher packetCipher =
                    PacketCipherFactory.getPacketCipher(
                            sshContext,
                            keySet.get(),
                            encryptionAlgorithm,
                            null,
                            CipherMode.ENCRYPT);
            sshContext.getPacketLayer().updateEncryptionCipher(packetCipher);

        } catch (IllegalArgumentException e) {
            LOGGER.warn(
                    "Caught an exception while trying to update the active {} cipher after handling a new keys message - workflow will continue with old cipher",
                    "encryption");
            LOGGER.debug(e);
        }

        LOGGER.info("Set Keys and Algorithms after sending the message");
    }

    private byte[] decryptSessionKey(ClientSessionKeyMessage message) throws CryptoException {
        byte[] sessionKey = message.getEncryptedSessioKey().getValue();
        LOGGER.debug("Enc. session Key: {}", ArrayConverter.bytesToHexString(sessionKey));
        if (sessionKey[0] == 0) {
            sessionKey = Arrays.copyOfRange(sessionKey, 1, sessionKey.length);
        }

        byte[] second_sessionkey = sessionKey.clone();

        CustomRsaPrivateKey hostPrivateKey;
        CustomRsaPrivateKey serverPrivatKey;

        SshPublicKey<?, ?> serverkey = sshContext.getServerKey();
        SshPublicKey<?, ?> hostKey = sshContext.getHostKey().orElseThrow();

        if (serverkey.getPrivateKey().isPresent()
                && serverkey.getPrivateKey().get() instanceof CustomRsaPrivateKey) {
            serverPrivatKey = (CustomRsaPrivateKey) serverkey.getPrivateKey().get();
        } else {
            throw new CryptoException("Private-Server-Key is Missing");
        }

        if (hostKey.getPrivateKey().isPresent()
                && hostKey.getPrivateKey().get() instanceof CustomRsaPrivateKey) {
            hostPrivateKey = (CustomRsaPrivateKey) hostKey.getPrivateKey().get();
        } else {
            throw new CryptoException("Private-Host-Key is Missing");
        }

        LOGGER.debug(
                "Server: \n Key: {} \n Mod: {}",
                ArrayConverter.bytesToRawHexString(
                        serverPrivatKey.getPrivateExponent().toByteArray()),
                ArrayConverter.bytesToRawHexString(serverPrivatKey.getModulus().toByteArray()));
        LOGGER.debug(
                "Host: \n Key: {} \n Mod: {}",
                ArrayConverter.bytesToRawHexString(
                        hostPrivateKey.getPrivateExponent().toByteArray()),
                ArrayConverter.bytesToRawHexString(hostPrivateKey.getModulus().toByteArray()));
        LOGGER.debug("Message: {}", ArrayConverter.bytesToRawHexString(sessionKey));

        AbstractCipher innerEncryption;
        AbstractCipher outerEncryption;

        boolean firstEncryptionSuccessfull = false;

        try {

            if (hostPrivateKey.getModulus().bitLength()
                    > serverPrivatKey.getModulus().bitLength()) {

                LOGGER.debug(
                        "Hostkeylenght: {}, ServerKeyLenght: {}",
                        hostPrivateKey.getModulus().bitLength(),
                        serverPrivatKey.getModulus().bitLength());
                LOGGER.debug(sessionKey.length);
                if (sessionKey.length > hostPrivateKey.getModulus().bitLength()) {

                    LOGGER.debug(
                            "Suspisius, the encrypted session key is longer then the host key modulus");
                }

                outerEncryption = CipherFactory.getRsaPkcs1Cipher(hostPrivateKey);
                sessionKey = outerEncryption.decrypt(sessionKey);

                firstEncryptionSuccessfull = true;

                innerEncryption = CipherFactory.getRsaPkcs1Cipher(serverPrivatKey);
                sessionKey = innerEncryption.decrypt(sessionKey);

            } else {
                outerEncryption = CipherFactory.getRsaPkcs1Cipher(serverPrivatKey);
                sessionKey = outerEncryption.decrypt(sessionKey);

                firstEncryptionSuccessfull = true;

                innerEncryption = CipherFactory.getRsaPkcs1Cipher(hostPrivateKey);
                sessionKey = innerEncryption.decrypt(sessionKey);
            }

        } catch (CryptoException e) {
            LOGGER.fatal(e);
            if (e.getCause() instanceof BadPaddingException) {
                if (firstEncryptionSuccessfull) {
                    LOGGER.fatal("Caused by BadPadding in second encryption");
                    // SEND Disconnect Message
                    // only the first one is correct, setting to 1
                    sshContext.setBbResult(1);
                } else {
                    LOGGER.fatal("Caused by BadPadding in first encryption");
                    // SEND Failure Message
                    // no key is correct - setting to 0
                    sshContext.setBbResult(0);
                }
            } else {
                sshContext.setBbResult(2);
            }
            // Both correct, setting BB Result to 2

            // throw new RuntimeException(e);
            // Set Session key to dummy value
            sessionKey = new byte[32];
        }

        // Set Sessionkey
        LOGGER.debug("The Session_key is {}", ArrayConverter.bytesToHexString(sessionKey));

        byte[] sessionID = sshContext.getSshv1SessionID();
        LOGGER.debug("Session_ID: {}", ArrayConverter.bytesToHexString(sessionID));
        int i = 0;

        for (byte sesseionByte : sessionID) {
            sessionKey[i] = (byte) (sesseionByte ^ sessionKey[i++]);
        }

        // Set Sessionkey
        LOGGER.debug("The Session_key is {}", ArrayConverter.bytesToHexString(sessionKey));
        return sessionKey;
    }

    @Override
    public void adjustContextAfterMessageSent() {

        if (sshContext.getContext().getConfig().isDoNotEncryptMessages()) {
            LOGGER.debug("Not enabling the encryption of packages due to configuration");
            return;
        }
        // We Send here, because we are in the perperator
        EncryptionAlgorithm encryptionAlgorithm;
        Chooser chooser = sshContext.getChooser();

        encryptionAlgorithm = chooser.getSendEncryptionAlgorithm();
        SshContext sshContext = chooser.getContext().getSshContext();

        KeyExchangeUtil.generateKeySet(sshContext);

        Optional<AbstractKeySet> keySet = sshContext.getKeySet();

        if (!keySet.isPresent()) {
            LOGGER.fatal("Keyset is not present, cannot go further");
            throw new RuntimeException();
        }

        AbstractKeySet activeKeySet = sshContext.getPacketLayer().getEncryptorCipher().getKeySet();
        EncryptionAlgorithm activeEncryptionAlgorithm =
                sshContext.getPacketLayer().getEncryptorCipher().getEncryptionAlgorithm();
        if (!sshContext.getConfig().getForcePacketCipherChange()
                && Objects.equals(activeKeySet, keySet.get())
                && encryptionAlgorithm == activeEncryptionAlgorithm
                && (encryptionAlgorithm.getType() == EncryptionAlgorithmType.AEAD)) {
            LOGGER.info(
                    "Key set and algorithms unchanged, not changing active decryption cipher - workflow will continue with old cipher");
            return;
        }

        try {
            PacketCipher packetCipher =
                    PacketCipherFactory.getPacketCipher(
                            sshContext,
                            keySet.get(),
                            encryptionAlgorithm,
                            null,
                            CipherMode.ENCRYPT);
            sshContext.getPacketLayer().updateEncryptionCipher(packetCipher);

        } catch (IllegalArgumentException e) {
            LOGGER.warn(
                    "Caught an exception while trying to update the active {} cipher after handling a new keys message - workflow will continue with old cipher",
                    "encryption");
            LOGGER.debug(e);
        }

        try {
            PacketCipher packetCipher =
                    PacketCipherFactory.getPacketCipher(
                            sshContext,
                            keySet.get(),
                            encryptionAlgorithm,
                            null,
                            CipherMode.DECRYPT);
            sshContext.getPacketLayer().updateDecryptionCipher(packetCipher);

        } catch (IllegalArgumentException e) {
            LOGGER.warn(
                    "Caught an exception while trying to update the active {} cipher after handling a new keys message - workflow will continue with old cipher",
                    "decryption");
            LOGGER.debug(e);
        }

        LOGGER.info("Set Keys and Algorithms after sending the message");
    }
}
