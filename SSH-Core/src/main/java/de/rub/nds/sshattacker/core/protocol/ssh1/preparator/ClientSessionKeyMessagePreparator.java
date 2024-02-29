/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.preparator;

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
        getObject().setAntiSpoofingCookie(chooser.getAntiSpoofingCookie());
    }

    private void prepareSessionID() {
        getObject().setAntiSpoofingCookie(chooser.getContext().getSshContext().getSshv1SessionID());
    }

    private void prepareEncryptionAlgorithm() {
        getObject()
                .setChosenCipherMethod(
                        chooser.getContext().getSshContext().getChosenCipherMethod());
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
        CustomRsaPublicKey hostPublickey;
        CustomRsaPublicKey serverPublicKey;

        SshPublicKey<?, ?> serverkey = chooser.getContext().getSshContext().getServerKey();
        SshPublicKey<?, ?> hostKey =
                chooser.getContext().getSshContext().getHostKey().orElseThrow();

        Random random = new Random();
        byte[] sessionKey = new byte[32];
        random.nextBytes(sessionKey);

        getObject().setPlaintextSessioKey(sessionKey);

        // byte[] plainSessionKey = sessionKey.clone();
        byte[] plainSessionKey = getObject().getPlaintextSessioKey().getValue();
        byte[] sharedSecret = plainSessionKey.clone();
        LOGGER.debug(
                "Original plain Session Key is: {}",
                ArrayConverter.bytesToRawHexString(sessionKey));
        LOGGER.debug(
                "Plain Session Key is: {}", ArrayConverter.bytesToRawHexString(plainSessionKey));

        // Use xored sessionkey for transmission
        byte[] sessionID = chooser.getContext().getSshContext().getSshv1SessionID();
        int i = 0;
        for (byte sesseionByte : sessionID) {
            sessionKey[i] = (byte) (sesseionByte ^ sessionKey[i++]);
        }

        LOGGER.debug("XORED Session Key is: {}", ArrayConverter.bytesToRawHexString(sessionKey));

        if (serverkey.getPublicKey() instanceof CustomRsaPublicKey) {
            serverPublicKey = (CustomRsaPublicKey) serverkey.getPublicKey();
        } else {
            throw new CryptoException("Public-Server-Key is Missing");
        }

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

                } else {

                    LOGGER.debug(
                            "Hostkeylenght: {}, ServerKeyLenght: {}",
                            hostPublickey.getModulus().bitLength(),
                            serverPublicKey.getModulus().bitLength());

                    innerEncryption = CipherFactory.getRsaPkcs1Cipher(serverPublicKey);
                    sessionKey = innerEncryption.encrypt(sessionKey);

                    outerEncryption = CipherFactory.getRsaPkcs1Cipher(hostPublickey);

                    sessionKey = outerEncryption.encrypt(sessionKey);
                }

            } catch (CryptoException e) {
                throw new RuntimeException(e);
            }
        }

        getObject().setEncryptedSessioKey(sessionKey);
        chooser.getContext().getSshContext().setSessionKey(plainSessionKey);
        chooser.getContext().getSshContext().setSharedSecret(sharedSecret);
        LOGGER.info(
                "Shared Secret should be: {}",
                ArrayConverter.bytesToRawHexString(
                        chooser.getContext().getSshContext().getSharedSecret().orElseThrow()));
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
