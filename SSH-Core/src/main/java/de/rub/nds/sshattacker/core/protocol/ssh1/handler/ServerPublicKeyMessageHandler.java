/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.handler;

import com.google.common.primitives.Bytes;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.AuthenticationMethodSSHv1;
import de.rub.nds.sshattacker.core.constants.CipherMethod;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.ServerPublicKeyMessage;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerPublicKeyMessageHandler extends SshMessageHandler<ServerPublicKeyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ServerPublicKeyMessageHandler(SshContext context) {
        super(context);
    }

    /*public HybridKeyExchangeReplyMessageHandler(
            SshContext context, HybridKeyExchangeReplyMessage message) {
        super(context, message);
    }*/

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

        // KeyExchangeUtil.handleHostKeyMessage(sshContext, message);
        // setRemoteValues(message);
        /*        sshContext.getChooser().getHybridKeyExchange().combineSharedSecrets();
        sshContext.setSharedSecret(
                sshContext.getChooser().getHybridKeyExchange().getSharedSecret());
        sshContext
                .getExchangeHashInputHolder()
                .setSharedSecret(sshContext.getChooser().getHybridKeyExchange().getSharedSecret());
        KeyExchangeUtil.computeExchangeHash(sshContext);
        */
        /*        KeyExchangeUtil.handleExchangeHashSignatureMessage(sshContext, message);*/
        /*
        KeyExchangeUtil.setSessionId(sshContext);
        KeyExchangeUtil.generateKeySet(sshContext);*/
    }

    private void setCipherMethod(ServerPublicKeyMessage message) {

        Collections.reverse(message.getSupportedCipherMethods());

        List<CipherMethod> supportedCipherMethods = message.getSupportedCipherMethods();

        // As the RFC States: prefer 3DES, then Blowfish, and then the rest.
        if (supportedCipherMethods.contains(CipherMethod.SSH_CIPHER_3DES)) {
            sshContext.setChosenCipherMethod(CipherMethod.SSH_CIPHER_3DES);
        } else if (supportedCipherMethods.contains(CipherMethod.SSH_CIPHER_BLOWFISH)) {
            sshContext.setChosenCipherMethod(CipherMethod.SSH_CIPHER_BLOWFISH);
        } else {
            CipherMethod chosenCipherMethod = supportedCipherMethods.get(0);
            sshContext.setChosenCipherMethod(chosenCipherMethod);
        }
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
            throw new RuntimeException();
        }

        SshPublicKey<?, ?> hostKey = message.getHostKey();
        if (hostKey.getPublicKey() instanceof CustomRsaPublicKey) {
            CustomRsaPublicKey rsaPublicKey = (CustomRsaPublicKey) hostKey.getPublicKey();
            hostModulus = rsaPublicKey.getModulus().toByteArray();
        } else {
            throw new RuntimeException();
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
