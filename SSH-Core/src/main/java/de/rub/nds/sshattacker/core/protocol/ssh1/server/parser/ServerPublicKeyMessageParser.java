/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.server.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.*;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageParser;
import de.rub.nds.sshattacker.core.protocol.ssh1.server.message.ServerPublicKeyMessage;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerPublicKeyMessageParser extends Ssh1MessageParser<ServerPublicKeyMessage> {
    private static final Logger LOGGER = LogManager.getLogger();

    public ServerPublicKeyMessageParser(SshContext context, InputStream stream) {
        super(stream);
    }

    private void parseHostKeyBytes(ServerPublicKeyMessage message) {

        int hostKeyBits = parseIntField(4);
        message.setHostKeyBitLenght(hostKeyBits);
        BigInteger exponent = parseMultiprecision();
        BigInteger modulus = parseMultiprecision();
        CustomRsaPublicKey publicKey = new CustomRsaPublicKey(exponent, modulus);
        message.setHostKey(new SshPublicKey<>(PublicKeyFormat.SSH_RSA, publicKey));

        LOGGER.debug(
                "Added Public Host Exponent with value {}",
                ArrayConverter.bytesToHexString(
                        message.getHostKey().getPublicKey().getPublicExponent().toByteArray()));

        LOGGER.debug(
                "Added Public Host Modulus with value {}",
                ArrayConverter.bytesToHexString(
                        message.getHostKey().getPublicKey().getModulus().toByteArray()));
    }

    private void parseServerKeyBytes(ServerPublicKeyMessage message) {

        int serverKeyBits = parseIntField(4);
        message.setServerKeyBitLenght(serverKeyBits);
        BigInteger exponent = parseMultiprecision();
        BigInteger modulus = parseMultiprecision();
        CustomRsaPublicKey publicKey = new CustomRsaPublicKey(exponent, modulus);
        message.setServerKey(new SshPublicKey<>(PublicKeyFormat.SSH_RSA, publicKey));

        LOGGER.debug(
                "Added Public Server Exponent with value {}",
                ArrayConverter.bytesToHexString(
                        message.getServerKey().getPublicKey().getPublicExponent().toByteArray()));

        LOGGER.debug(
                "Added Public Server Modulus with value {}",
                ArrayConverter.bytesToHexString(
                        message.getServerKey().getPublicKey().getModulus().toByteArray()));
    }

    private void parseAntiSpoofingCookie(ServerPublicKeyMessage message) {
        message.setAntiSpoofingCookie(parseByteArrayField(8));
        LOGGER.debug("AntiSpoofingCookie: {}", message.getAntiSpoofingCookie().getValue());
    }

    private void parseProtocolFlags(ServerPublicKeyMessage message) {
        message.setProtocolFlagMask(parseIntField(4));
        LOGGER.debug("Protocol Flags Mask {}", message.getProtocolFlagMask().getValue());

        int flagMask = message.getProtocolFlagMask().getValue();
        String stringProtocolMask = Integer.toBinaryString(flagMask);
        List<ProtocolFlag> chosenProtocolFlags = new ArrayList<>();
        for (int i = 0; i < stringProtocolMask.length(); i++) {
            if (stringProtocolMask.charAt(i) == '1') {
                int id = stringProtocolMask.length() - 1 - i;
                chosenProtocolFlags.add(ProtocolFlag.fromId(id));
                LOGGER.debug("Parsed ProtocolFlags {} at id {}", ProtocolFlag.fromId(id), id);
            }
        }

        message.setChosenProtocolFlags(chosenProtocolFlags);
    }

    private void parseCipherMask(ServerPublicKeyMessage message) {
        message.setCipherMask(parseIntField(4));
        LOGGER.debug(
                "CipherMask: {}", ArrayConverter.intToBytes(message.getCipherMask().getValue(), 4));

        int cipherMask = message.getCipherMask().getValue();
        String stringCipherMask = Integer.toBinaryString(cipherMask);
        List<CipherMethod> supportedCipherMethods = new ArrayList<>();
        for (int i = 0; i < stringCipherMask.length(); i++) {
            if (stringCipherMask.charAt(i) == '1') {
                int id = stringCipherMask.length() - 1 - i;
                supportedCipherMethods.add(CipherMethod.fromId(id));
                LOGGER.debug("Parsed Ciphers {} at id {}", CipherMethod.fromId(id), id);
            }
        }
        message.setSupportedCipherMethods(supportedCipherMethods);
    }

    private void parseAuthMask(ServerPublicKeyMessage message) {
        message.setAuthMask(parseIntField(4));
        LOGGER.debug(
                "AuthMask: {}", ArrayConverter.intToBytes(message.getAuthMask().getValue(), 4));

        int authMask = message.getAuthMask().getValue();
        String stringAuthMask = Integer.toBinaryString(authMask);
        List<AuthenticationMethodSSHv1> supportedAuthenticationMethods = new ArrayList<>();
        for (int i = 0; i < stringAuthMask.length(); i++) {
            if (stringAuthMask.charAt(i) == '1') {
                int id = stringAuthMask.length() - 1 - i;
                supportedAuthenticationMethods.add(AuthenticationMethodSSHv1.fromId(id));
                LOGGER.debug(
                        "Parsed Authentiationmethod {} at id {}",
                        AuthenticationMethodSSHv1.fromId(id),
                        id);
            }
        }

        message.setSupportedAuthenticationMethods(supportedAuthenticationMethods);
    }

    @Override
    protected void parseMessageSpecificContents(ServerPublicKeyMessage message) {
        parseAntiSpoofingCookie(message);
        parseServerKeyBytes(message);
        parseHostKeyBytes(message);
        parseProtocolFlags(message);
        parseCipherMask(message);
        parseAuthMask(message);
    }

    @Override
    public void parse(ServerPublicKeyMessage message) {
        parseProtocolMessageContents(message);
    }
}
