/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.preparator;

import com.google.common.primitives.Bytes;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.*;
import de.rub.nds.sshattacker.core.crypto.cipher.AbstractCipher;
import de.rub.nds.sshattacker.core.crypto.cipher.CipherFactory;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.ClientSessionKeyMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ClientSessionKeyMessagePreparator
        extends SshMessagePreparator<ClientSessionKeyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ClientSessionKeyMessagePreparator(Chooser chooser, ClientSessionKeyMessage message) {
        super(chooser, message, MessageIdConstantSSH1.SSH_CMSG_SESSION_KEY);
    }

    private void prepareAntiSpoofingCookie() {
        getObject()
                .setAntiSpoofingCookie(
                        chooser.getContext().getSshContext().getAntiSpoofingCookie());
    }

    private void prepareSessionID() {
        byte[] serverModulus;
        byte[] hostModulus;
        byte[] cookie;
        SshPublicKey<?, ?> serverkey = chooser.getContext().getSshContext().getServerKey();

        if (serverkey.getPublicKey() instanceof CustomRsaPublicKey) {
            CustomRsaPublicKey rsaPublicKey = (CustomRsaPublicKey) serverkey.getPublicKey();
            serverModulus = rsaPublicKey.getModulus().toByteArray();
        } else {
            throw new RuntimeException();
        }

        SshPublicKey<?, ?> hostKey =
                chooser.getContext().getSshContext().getHostKey().orElseThrow();
        if (hostKey.getPublicKey() instanceof CustomRsaPublicKey) {
            CustomRsaPublicKey rsaPublicKey = (CustomRsaPublicKey) hostKey.getPublicKey();
            hostModulus = rsaPublicKey.getModulus().toByteArray();
        } else {
            throw new RuntimeException();
        }

        // DEBUG CODE
        if (hostModulus[0] == 0) {
            hostModulus = Arrays.copyOfRange(hostModulus, 1, hostModulus.length);
        }
        // DEBUG CODE

        // DEBUG CODE
        if (serverModulus[0] == 0) {
            serverModulus = Arrays.copyOfRange(serverModulus, 1, serverModulus.length);
        }
        // DEBUG CODE

        cookie = chooser.getContext().getSshContext().getAntiSpoofingCookie();

        LOGGER.debug("Servermodulus for SessionID: {}", serverModulus);
        LOGGER.debug("Hostmodulus for SessionID: {}", hostModulus);
        LOGGER.debug("Cookie for SessionID: {}", cookie);

        MessageDigest md;
        try {
            md = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        md.update(Bytes.concat(hostModulus, serverModulus, cookie));
        // md.update(Bytes.concat(serverModulus, hostModulus, cookie));
        byte[] sessionID = md.digest();
        LOGGER.debug("Session-ID {}", ArrayConverter.bytesToHexString(sessionID));
        getObject().setSshv1SessionID(sessionID);
        chooser.getContext().getSshContext().setSessionID(sessionID);
        chooser.getContext().getSshContext().setSshv1SessionID(sessionID);
    }

    private void prepareEncryptionAlgorithm() {
        // Choose Encryption Type
        CipherMethod chosenCipherMethod;
        if (!chooser.getContext().getSshContext().getSupportedCipherMethods().isEmpty()) {
            chosenCipherMethod =
                    chooser.getContext().getSshContext().getSupportedCipherMethods().get(0);
            if (chooser.getContext().getSshContext().getSupportedCipherMethods().size() > 1) {
                chosenCipherMethod =
                        chooser.getContext().getSshContext().getSupportedCipherMethods().get(1);
            }
            chooser.getContext().getSshContext().setChosenCipherMethod(chosenCipherMethod);

            // Derive correct Encryption Algorithm
            EncryptionAlgorithm encryptionAlgorithm;
            switch (chosenCipherMethod) {
                case SSH_CIPHER_3DES:
                    encryptionAlgorithm = EncryptionAlgorithm.TRIPLE_DES_CBC;
                    break;
                case SSH_CIPHER_NONE:
                    encryptionAlgorithm = EncryptionAlgorithm.NONE;
                    break;
                case SSH_CIPHER_IDEA:
                    encryptionAlgorithm =
                            EncryptionAlgorithm.IDEA_CTR; // Wrong, needts to be IDEA_CFB!
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

            getObject().setChosenCipherMethod(chosenCipherMethod);
        }
        LOGGER.info(
                "Choose Ciphermethod: {}",
                chooser.getContext().getSshContext().getChosenCipherMethod());
    }

    private void prepareProtoclFlags() {
        LOGGER.debug("Prepare Protocol Flags");
        int flagMask = 0;
        List<ProtocolFlag> chosenProtocolFlags = chooser.getConfig().getChosenProtocolFlags();
        for (ProtocolFlag flag : chosenProtocolFlags) {
            int shifter = flag.getId();
            int helper = 1;

            helper = helper << shifter;
            flagMask = flagMask | helper;
            LOGGER.debug("got {} shifted {}-times", ProtocolFlag.fromId(flag.getId()), shifter);
        }
        getObject().setChosenProtocolFlags(chooser.getConfig().getChosenProtocolFlags());

        getObject().setProtocolFlagMask(flagMask);
    }

    private void prepareSessionKey() throws CryptoException {
        Random random = new Random();
        byte[] sessionKey = new byte[32];
        byte[] plainSessionKey;
        random.nextBytes(sessionKey);

        plainSessionKey = sessionKey.clone();

        // byte[] sessionID = getObject().getSshv1SessionID().getValue();
        byte[] sessionID = chooser.getContext().getSshContext().getSshv1SessionID();
        LOGGER.debug("Session id = {}", ArrayConverter.bytesToHexString(sessionID));
        LOGGER.debug(
                "the not XORED Session_key is {}", ArrayConverter.bytesToHexString(sessionKey));

        int i = 0;
        for (byte sesseionByte : sessionID) {
            sessionKey[i] = (byte) (sesseionByte ^ sessionKey[i++]);
        }

        LOGGER.debug(
                "the Plain Session_key is {}", ArrayConverter.bytesToHexString(plainSessionKey));

        LOGGER.debug("the XORED Session_key is {}", ArrayConverter.bytesToHexString(sessionKey));
        // plainSessionKey = sessionKey;

        CustomRsaPublicKey hostPublickey;
        CustomRsaPublicKey serverPublicKey;

        SshPublicKey<?, ?> serverkey = chooser.getContext().getSshContext().getServerKey();

        if (serverkey.getPublicKey() instanceof CustomRsaPublicKey) {
            serverPublicKey = (CustomRsaPublicKey) serverkey.getPublicKey();
        } else {
            throw new CryptoException("Public-Server-Key is Missing");
        }

        SshPublicKey<?, ?> hostKey =
                chooser.getContext().getSshContext().getHostKey().orElseThrow();
        if (hostKey.getPublicKey() instanceof CustomRsaPublicKey) {
            hostPublickey = (CustomRsaPublicKey) hostKey.getPublicKey();
        } else {
            throw new CryptoException("Public-Host-Key is Missing");
        }

        AbstractCipher innerEncryption;
        AbstractCipher outerEncryption;

        if (hostPublickey != null && serverPublicKey != null) {
            try {

                if (hostPublickey.getModulus().bitLength()
                        < serverPublicKey.getModulus().bitLength()) {

                    LOGGER.debug(
                            "Hostkeylenght: {}, ServerKeyLenght: {}",
                            hostPublickey.getModulus().bitLength(),
                            serverPublicKey.getModulus().bitLength());

                    innerEncryption = CipherFactory.getRsaPkcs1Cipher(hostPublickey);
                    sessionKey = innerEncryption.encrypt(sessionKey);

                    outerEncryption = CipherFactory.getRsaPkcs1Cipher(serverPublicKey);

                    sessionKey = outerEncryption.encrypt(sessionKey);

                    LOGGER.debug("Scucessfull Decrypted, Sanity-Check passed");
                } else {

                    LOGGER.debug(
                            "Hostkeylenght: {}, ServerKeyLenght: {}",
                            hostPublickey.getModulus().bitLength(),
                            serverPublicKey.getModulus().bitLength());

                    innerEncryption = CipherFactory.getRsaPkcs1Cipher(serverPublicKey);
                    sessionKey = innerEncryption.encrypt(sessionKey);

                    outerEncryption = CipherFactory.getRsaPkcs1Cipher(hostPublickey);

                    sessionKey = outerEncryption.encrypt(sessionKey);

                    LOGGER.debug("Scucessfull Decrypted, Sanity-Check passed");
                }

            } catch (CryptoException e) {
                throw new RuntimeException(e);
            }
        }

        // Set Sessionkey
        getObject().setEncryptedSessioKey(sessionKey);
        chooser.getContext().getSshContext().setSessionKey(plainSessionKey);
        chooser.getContext().getSshContext().setSharedSecret(plainSessionKey);
        // LOGGER.debug("The Session_key is {}", ArrayConverter.bytesToHexString(plainSessionKey));
    }

    @Override
    public void prepareMessageSpecificContents() {
        LOGGER.debug("Preparring now...");
        prepareSessionID();
        prepareEncryptionAlgorithm();
        prepareProtoclFlags();
        prepareAntiSpoofingCookie();
        try {
            prepareSessionKey();
        } catch (CryptoException e) {
            LOGGER.fatal("Error while encrypting Session key {}.", e.getMessage());
            throw new RuntimeException(e);
        }
    }
}
