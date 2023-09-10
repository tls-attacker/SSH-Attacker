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
import java.util.List;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ClientSessionKeyMessagePreparator
        extends SshMessagePreparator<ClientSessionKeyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();
    private HybridKeyExchangeCombiner combiner;

    public ClientSessionKeyMessagePreparator(
            Chooser chooser, ClientSessionKeyMessage message, HybridKeyExchangeCombiner combiner) {
        super(chooser, message, MessageIdConstantSSH1.SSH_CMSG_SESSION_KEY);
        this.combiner = combiner;
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

        cookie = chooser.getContext().getSshContext().getAntiSpoofingCookie();

        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        md.update(Bytes.concat(serverModulus, hostModulus, cookie));
        byte[] sessionID = md.digest();
        LOGGER.debug("Session-ID {}", ArrayConverter.bytesToHexString(sessionID));
        getObject().setSshv1SessionID(sessionID);
        chooser.getContext().getSshContext().setSessionID(sessionID);
    }

    private void prepareEncryptionAlgorithm() {
        // Choose Encryption Type
        CipherMethod chosenCipherMethod;
        if (!chooser.getContext().getSshContext().getSupportedCipherMethods().isEmpty()) {
            chosenCipherMethod =
                    chooser.getContext().getSshContext().getSupportedCipherMethods().get(0);
            chooser.getContext().getSshContext().setChosenCipherMethod(chosenCipherMethod);
            getObject().setChosenCipherMethod(chosenCipherMethod);
        }
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

    private void prepareSessionKey() {
        Random random = new Random();
        byte[] sessionKey = new byte[32];
        random.nextBytes(sessionKey);

        byte[] sessionID = getObject().getSshv1SessionID().getValue();
        LOGGER.debug(
                "Session-ID {} | SessionKey before {}",
                ArrayConverter.bytesToHexString(sessionID),
                ArrayConverter.bytesToHexString(sessionKey));

        int i = 0;
        for (byte sesseionByte : sessionID) {
            sessionKey[i] = (byte) (sesseionByte ^ sessionKey[i++]);
        }

        LOGGER.debug(
                "Session-ID {} | SessionKey after {}",
                ArrayConverter.bytesToHexString(sessionID),
                ArrayConverter.bytesToHexString(sessionKey));

        CustomRsaPublicKey hostPublickey;
        CustomRsaPublicKey serverPublicKey;

        SshPublicKey<?, ?> serverkey = chooser.getContext().getSshContext().getServerKey();

        if (serverkey.getPublicKey() instanceof CustomRsaPublicKey) {
            serverPublicKey = (CustomRsaPublicKey) serverkey.getPublicKey();
        } else {
            throw new RuntimeException();
        }

        SshPublicKey<?, ?> hostKey =
                chooser.getContext().getSshContext().getHostKey().orElseThrow();
        if (hostKey.getPublicKey() instanceof CustomRsaPublicKey) {
            hostPublickey = (CustomRsaPublicKey) hostKey.getPublicKey();
        } else {
            throw new RuntimeException();
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
        chooser.getContext().getSshContext().setSessionKey(sessionKey);
        LOGGER.debug("The Session_key is {}", ArrayConverter.bytesToHexString(sessionKey));
    }

    @Override
    public void prepareMessageSpecificContents() {
        LOGGER.debug("Preparring now...");
        prepareSessionID();
        prepareEncryptionAlgorithm();
        prepareProtoclFlags();
        prepareAntiSpoofingCookie();
        prepareSessionKey();
    }
}
