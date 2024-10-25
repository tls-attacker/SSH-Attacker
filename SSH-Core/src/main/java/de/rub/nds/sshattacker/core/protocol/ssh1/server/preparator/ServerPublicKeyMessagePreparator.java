/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.server.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.*;
import de.rub.nds.sshattacker.core.crypto.keys.*;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessagePreparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.server.message.ServerPublicKeyMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerPublicKeyMessagePreparator
        extends Ssh1MessagePreparator<ServerPublicKeyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();
    private SshPublicKey<CustomRsaPublicKey, CustomRsaPrivateKey> serverKey;
    private SshPublicKey<CustomRsaPublicKey, CustomRsaPrivateKey> hostkey;

    public ServerPublicKeyMessagePreparator(Chooser chooser, ServerPublicKeyMessage message) {
        super(chooser, message, MessageIdConstantSSH1.SSH_SMSG_PUBLIC_KEY);
    }

    @Override
    public void prepareMessageSpecificContents() {
        LOGGER.debug("Preparring now...");
        prepareServerKey();
        prepareHostKey();
        prepareAntiSpoofingCookie();
        prepareSupportedCipers();
        prepareSupportedAuthenticationMethods();
        prepareFlags();
        prepareSessionID();
    }

    public void prepareHostKey() {

        List<SshPublicKey<?, ?>> hostkeys = chooser.getConfig().getHostKeys();
        if (!hostkeys.isEmpty()) {
            SshPublicKey<?, ?> key = hostkeys.get(0);
            if (key.getPrivateKey().isPresent()) {
                CustomRsaPrivateKey privkey = (CustomRsaPrivateKey) key.getPrivateKey().get();
                CustomRsaPublicKey pubkey = (CustomRsaPublicKey) key.getPublicKey();
                hostkey = new SshPublicKey<>(PublicKeyFormat.SSH_RSA, pubkey, privkey);
            }
        }

        getObject().setHostKey(hostkey);
        chooser.getContext().getSshContext().setHostKey(hostkey);

        getObject().setHostKeyBitLenght(hostkey.getPublicKey().getModulus().bitLength());

        LOGGER.debug(
                "[bro] Hostkey Exponent: {}",
                ArrayConverter.bytesToHexString(
                        hostkey.getPublicKey().getPublicExponent().toByteArray()));
        LOGGER.debug(
                "[bro] Hostkey Modulus: {}",
                ArrayConverter.bytesToHexString(hostkey.getPublicKey().getModulus().toByteArray()));
    }

    public void prepareServerKey() {

        List<SshPublicKey<?, ?>> serverKeys = chooser.getConfig().getServerKeys();
        if (!serverKeys.isEmpty()) {
            SshPublicKey<?, ?> key = serverKeys.get(0);
            if (key.getPrivateKey().isPresent()) {
                CustomRsaPrivateKey privkey = (CustomRsaPrivateKey) key.getPrivateKey().get();
                CustomRsaPublicKey pubkey = (CustomRsaPublicKey) key.getPublicKey();
                serverKey = new SshPublicKey<>(PublicKeyFormat.SSH_RSA, pubkey, privkey);
            }
        }

        chooser.getContext().getSshContext().setServerKey(serverKey);
        getObject().setServerKey(serverKey);
        getObject().setServerKeyBitLenght(serverKey.getPublicKey().getModulus().bitLength());

        LOGGER.debug(
                "[bro] ServerKey Exponent: {}",
                ArrayConverter.bytesToHexString(
                        serverKey.getPublicKey().getPublicExponent().toByteArray()));
        LOGGER.debug(
                "[bro] ServerKey Modulus: {}",
                ArrayConverter.bytesToHexString(
                        serverKey.getPublicKey().getModulus().toByteArray()));
    }

    public void prepareSupportedCipers() {
        int ciphers = 0;

        List<CipherMethod> supportedCipherMethods = chooser.getConfig().getSupportedCipherMethods();

        for (CipherMethod method : supportedCipherMethods) {
            int shifter = method.getId();
            int helper = 1;

            helper = helper << shifter;
            ciphers = ciphers | helper;
            LOGGER.debug("got {} shifted {}-times", CipherMethod.fromId(method.getId()), shifter);
        }

        getObject().setCipherMask(ciphers);

        getObject().setSupportedCipherMethods(chooser.getConfig().getSupportedCipherMethods());
    }

    public void prepareSupportedAuthenticationMethods() {
        int authMask = 0;
        List<AuthenticationMethodSSHv1> supportedAuthenticationMethods =
                chooser.getConfig().getSupportedAuthenticationMethods();

        for (AuthenticationMethodSSHv1 method : supportedAuthenticationMethods) {
            int shifter = method.getId();
            int helper = 1;

            helper = helper << shifter;
            authMask = authMask | helper;
            LOGGER.debug(
                    "got {} shifted {}-times",
                    AuthenticationMethodSSHv1.fromId(method.getId()),
                    shifter);
        }

        getObject()
                .setSupportedAuthenticationMethods(
                        chooser.getConfig().getSupportedAuthenticationMethods());

        getObject().setAuthMask(authMask);
    }

    public void prepareAntiSpoofingCookie() {
        getObject().setAntiSpoofingCookie(chooser.getConfig().getAntiSpoofingCookie());
    }

    public void prepareFlags() {
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

    private void prepareSessionID() {
        byte[] serverModulus;
        byte[] hostModulus;
        byte[] cookie;
        SshPublicKey<?, ?> serverkey = chooser.getContext().getSshContext().getServerKey();

        if (serverkey.getPublicKey() instanceof CustomRsaPublicKey) {
            CustomRsaPublicKey rsaPublicKey = (CustomRsaPublicKey) serverkey.getPublicKey();
            serverModulus = rsaPublicKey.getModulus().toByteArray();
        } else {
            throw new RuntimeException("Server public key is not a rsa key");
        }

        SshPublicKey<?, ?> hostKey = chooser.getContext().getSshContext().getHostKey().orElse(null);
        if (hostKey.getPublicKey() instanceof CustomRsaPublicKey) {
            CustomRsaPublicKey rsaPublicKey = (CustomRsaPublicKey) hostKey.getPublicKey();
            hostModulus = rsaPublicKey.getModulus().toByteArray();
        } else {
            throw new RuntimeException("Host public key is not a rsa key");
        }

        cookie = chooser.getAntiSpoofingCookie();

        // Remove sign-byte if present
        if (hostModulus[0] == 0) {
            hostModulus = Arrays.copyOfRange(hostModulus, 1, hostModulus.length);
        }
        if (serverModulus[0] == 0) {
            serverModulus = Arrays.copyOfRange(serverModulus, 1, serverModulus.length);
        }

        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        md.update(ArrayConverter.concatenate(hostModulus, serverModulus, cookie));
        byte[] sessionID = md.digest();
        LOGGER.debug("Session-ID {}", ArrayConverter.bytesToHexString(sessionID));
        chooser.getContext().getSshContext().setSessionID(sessionID);
        chooser.getContext().getSshContext().setSshv1SessionID(sessionID);
    }
}
