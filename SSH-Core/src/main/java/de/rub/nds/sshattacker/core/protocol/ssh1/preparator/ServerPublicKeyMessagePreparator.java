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
import de.rub.nds.sshattacker.core.crypto.keys.*;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.ServerPublicKeyMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerPublicKeyMessagePreparator extends SshMessagePreparator<ServerPublicKeyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();
    private HybridKeyExchangeCombiner combiner;

    private SshPublicKey<CustomRsaPublicKey, CustomRsaPrivateKey> serverKey;

    public ServerPublicKeyMessagePreparator(
            Chooser chooser, ServerPublicKeyMessage message, HybridKeyExchangeCombiner combiner) {
        super(chooser, message, MessageIdConstantSSH1.SSH_SMSG_PUBLIC_KEY);
        this.combiner = combiner;
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
        SshPublicKey<?, ?> opt_hostKey = chooser.getConfig().getHostKeys().get(0);

        CustomRsaPublicKey publicKey = (CustomRsaPublicKey) opt_hostKey.getPublicKey();
        if (!opt_hostKey.getPrivateKey().isPresent()) {
            LOGGER.warn("no privat key defined for hostkey");
        }
        if (opt_hostKey.getPublicKeyFormat().getName().equals(PublicKeyFormat.SSH_RSA.getName())) {
            LOGGER.warn(
                    "the Host-Key is not formated as RSA Key-Type, it is {}",
                    opt_hostKey.getPublicKeyFormat().getName());
        }
        CustomRsaPrivateKey privateKey = (CustomRsaPrivateKey) opt_hostKey.getPrivateKey().get();

        SshPublicKey<CustomRsaPublicKey, CustomRsaPrivateKey> hostKey =
                new SshPublicKey<>(PublicKeyFormat.SSH_RSA, publicKey, privateKey);

        getObject().setHostKey(hostKey);
        chooser.getContext().getSshContext().setHostKey(hostKey);

        getObject().setHostKeyBitLenght(publicKey.getModulus().bitLength());

        LOGGER.debug(
                "[bro] Hostkey Exponent: {}",
                ArrayConverter.bytesToHexString(publicKey.getPublicExponent().toByteArray()));
        LOGGER.debug(
                "[bro] Hostkey Modulus: {}",
                ArrayConverter.bytesToHexString(publicKey.getModulus().toByteArray()));
    }

    public void prepareServerKey() {

        List<SshPublicKey<?, ?>> serverKeys = chooser.getConfig().getServerKeys();
        if (!serverKeys.isEmpty()) {
            SshPublicKey<?, ?> key = serverKeys.get(0);
            if (key.getPrivateKey().isPresent()) {
                CustomRsaPrivateKey privkey = (CustomRsaPrivateKey) key.getPrivateKey().get();
                CustomRsaPublicKey pubkey = (CustomRsaPublicKey) key.getPublicKey();
                this.serverKey = new SshPublicKey<>(PublicKeyFormat.SSH_RSA, pubkey, privkey);
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
            throw new RuntimeException();
        }

        SshPublicKey<?, ?> hostKey = chooser.getConfig().getHostKeys().get(0);
        if (hostKey.getPublicKey() instanceof CustomRsaPublicKey) {
            CustomRsaPublicKey rsaPublicKey = (CustomRsaPublicKey) hostKey.getPublicKey();
            hostModulus = rsaPublicKey.getModulus().toByteArray();
        } else {
            throw new RuntimeException();
        }

        cookie = chooser.getAntiSpoofingCookie();

        // Remove sign-byte if present
        if (hostModulus[0] == 0) {
            hostModulus = Arrays.copyOfRange(hostModulus, 1, hostModulus.length);
        }
        if (serverModulus[0] == 0) {
            serverModulus = Arrays.copyOfRange(serverModulus, 1, serverModulus.length);
        }

        /*
                LOGGER.debug("Servermodulus for SessionID: {}", serverModulus);
                LOGGER.debug("Hostmodulus for SessionID: {}", hostModulus);
                LOGGER.debug("Cookie for SessionID: {}", cookie);
        */

        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        md.update(Bytes.concat(hostModulus, serverModulus, cookie));
        // md.update(Bytes.concat(serverModulus, hostModulus, cookie));
        byte[] sessionID = md.digest();
        LOGGER.debug("Session-ID {}", ArrayConverter.bytesToHexString(sessionID));
        chooser.getContext().getSshContext().setSessionID(sessionID);
        chooser.getContext().getSshContext().setSshv1SessionID(sessionID);
    }
}
