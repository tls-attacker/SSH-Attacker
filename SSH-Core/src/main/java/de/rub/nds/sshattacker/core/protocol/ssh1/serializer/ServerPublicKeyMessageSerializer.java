/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.HybridKeyExchangeCombiner;
import de.rub.nds.sshattacker.core.crypto.checksum.CRC;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.ServerPublicKeyMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerPublicKeyMessageSerializer extends SshMessageSerializer<ServerPublicKeyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();
    private HybridKeyExchangeCombiner combiner;

    public ServerPublicKeyMessageSerializer(
            ServerPublicKeyMessage message, HybridKeyExchangeCombiner combiner) {
        super(message);
        this.combiner = combiner;
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeCookie();
        serializeServerKeyBytes();
        serializeHostKeyBytes();
        serializeProtocolFlags();
        serializeCipherMask();
        serializeSupportedAuthMask();
        serializCRCChecksum();
    }

    private void serializeProtocolFlags() {
        int flags = message.getProtocolFlagMask().getValue();
        appendInt(flags, 4);
        LOGGER.debug("Flags:  " + Integer.toBinaryString(flags));
    }

    private void serializeCipherMask() {
        int ciphers = message.getCipherMask().getValue();
        appendInt(ciphers, 4);
        LOGGER.debug("Cipher:  " + Integer.toBinaryString(ciphers));
    }

    private void serializeSupportedAuthMask() {
        int authMask = message.getAuthMask().getValue();
        appendInt(authMask, 4);
        LOGGER.debug("AuthMasks:  " + Integer.toBinaryString(authMask));
    }

    private void serializCRCChecksum() {
        CRC crc32 = new CRC(32, 0x0104C11DB7L, 0, true, true, 0);
        byte[] checksum = ArrayConverter.longToBytes(crc32.calculateCRC(getAlreadySerialized()), 4);
        appendBytes(checksum);
        LOGGER.debug("CRC:  " + ArrayConverter.bytesToRawHexString(checksum));
    }

    private void serializeCookie() {
        appendBytes(message.getAntiSpoofingCookie().getValue());
        LOGGER.debug(
                "Cookie: "
                        + ArrayConverter.bytesToRawHexString(
                                message.getAntiSpoofingCookie().getValue()));
    }

    private void serializeServerKeyBytes() {
        appendInt(message.getServerKeyBitLenght().getValue(), 4);

        appendMultiPrecision(message.getServerKey().getPublicKey().getPublicExponent());
        LOGGER.debug(
                "Added Public Host Exponent with value {}",
                ArrayConverter.bytesToHexString(
                        message.getServerKey().getPublicKey().getPublicExponent().toByteArray()));

        appendMultiPrecision(message.getServerKey().getPublicKey().getModulus());
        LOGGER.debug(
                "Added Public Host Modulus with value {}",
                ArrayConverter.bytesToHexString(
                        message.getServerKey().getPublicKey().getModulus().toByteArray()));
    }

    private void serializeHostKeyBytes() {

        appendInt(message.getHostKeyBitLenght().getValue(), 4);

        appendMultiPrecision(message.getHostKey().getPublicKey().getPublicExponent());
        LOGGER.debug(
                "Added Public Host Exponent with value {}",
                ArrayConverter.bytesToHexString(
                        message.getHostKey().getPublicKey().getPublicExponent().toByteArray()));

        appendMultiPrecision(message.getHostKey().getPublicKey().getModulus());
        LOGGER.debug(
                "Added Public Host Modulus with value {}",
                ArrayConverter.bytesToHexString(
                        message.getHostKey().getPublicKey().getModulus().toByteArray()));
    }
}
