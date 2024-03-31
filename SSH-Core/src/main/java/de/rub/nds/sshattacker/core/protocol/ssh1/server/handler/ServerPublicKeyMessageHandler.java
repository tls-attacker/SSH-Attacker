/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.server.handler;

import com.google.common.primitives.Bytes;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.AuthenticationMethodSSHv1;
import de.rub.nds.sshattacker.core.constants.CipherMethod;
import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithm;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageHandler;
import de.rub.nds.sshattacker.core.protocol.ssh1.server.message.ServerPublicKeyMessage;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerPublicKeyMessageHandler extends Ssh1MessageHandler<ServerPublicKeyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ServerPublicKeyMessageHandler(SshContext sshContext) {
        super(sshContext);
    }

    @Override
    public void adjustContext(ServerPublicKeyMessage message) {

        sshContext.setServerKey(message.getServerKey());
        sshContext.setHostKey(message.getHostKey());
        sshContext.setAntiSpoofingCookie(message.getAntiSpoofingCookie().getValue());
        sshContext.setSupportedCipherMethods(message.getSupportedCipherMethods());
        sshContext.setSupportedAuthenticationMethods(message.getSupportedAuthenticationMethods());
        sshContext.setChosenProtocolFlags(message.getChosenProtocolFlags());

        caluculateSessionId(message);
        setCipherMethod(message);
        setAuthenticationMethod(message);
    }

    private void setCipherMethod(ServerPublicKeyMessage message) {

        Collections.reverse(message.getSupportedCipherMethods());

        List<CipherMethod> supportedCipherMethods = message.getSupportedCipherMethods();
        CipherMethod chosenCipherMethod;
        // As the RFC States: prefer 3DES, then Blowfish, and then the rest.
        if (supportedCipherMethods.contains(CipherMethod.SSH_CIPHER_3DES)) {
            sshContext.setChosenCipherMethod(CipherMethod.SSH_CIPHER_3DES);
        } else if (supportedCipherMethods.contains(CipherMethod.SSH_CIPHER_BLOWFISH)) {
            sshContext.setChosenCipherMethod(CipherMethod.SSH_CIPHER_BLOWFISH);
        } else {
            chosenCipherMethod = supportedCipherMethods.get(0);
            sshContext.setChosenCipherMethod(chosenCipherMethod);
        }

        LOGGER.debug("Set Ciphermethod {}", sshContext.getChosenCipherMethod());

        EncryptionAlgorithm encryptionAlgorithm;
        switch (sshContext.getChosenCipherMethod()) {
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
                        sshContext.getChosenCipherMethod());
        }

        LOGGER.info("Successfulle applied Encryption Algorihm {}", encryptionAlgorithm);

        sshContext.setEncryptionAlgorithmClientToServer(encryptionAlgorithm);
        sshContext.setEncryptionAlgorithmServerToClient(encryptionAlgorithm);
    }

    private void setAuthenticationMethod(ServerPublicKeyMessage message) {

        Collections.reverse(message.getSupportedAuthenticationMethods());
        List<AuthenticationMethodSSHv1> supportedAuthenticationMethods =
                message.getSupportedAuthenticationMethods();
        sshContext.setChosenAuthenticationMethod(supportedAuthenticationMethods.get(0));
    }

    private void caluculateSessionId(ServerPublicKeyMessage message) {

        byte[] serverModulus;
        byte[] hostModulus;
        byte[] cookie;
        SshPublicKey<?, ?> serverkey = message.getServerKey();

        if (serverkey.getPublicKey() instanceof CustomRsaPublicKey) {
            CustomRsaPublicKey rsaPublicKey = (CustomRsaPublicKey) serverkey.getPublicKey();
            serverModulus = rsaPublicKey.getModulus().toByteArray();
        } else {
            throw new RuntimeException("Server public key is not a rsa key");
        }

        SshPublicKey<?, ?> hostKey = message.getHostKey();
        if (hostKey.getPublicKey() instanceof CustomRsaPublicKey) {
            CustomRsaPublicKey rsaPublicKey = (CustomRsaPublicKey) hostKey.getPublicKey();
            hostModulus = rsaPublicKey.getModulus().toByteArray();
        } else {
            throw new RuntimeException("Host public key is not a rsa key");
        }

        // Remove sign-byte if present
        if (hostModulus[0] == 0) {
            hostModulus = Arrays.copyOfRange(hostModulus, 1, hostModulus.length);
        }
        if (serverModulus[0] == 0) {
            serverModulus = Arrays.copyOfRange(serverModulus, 1, serverModulus.length);
        }

        cookie = message.getAntiSpoofingCookie().getValue();

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
        byte[] sessionID = md.digest();
        LOGGER.debug("Session-ID {}", ArrayConverter.bytesToHexString(sessionID));
        sshContext.setSessionID(sessionID);
        sshContext.setSshv1SessionID(sessionID);
    }
}
