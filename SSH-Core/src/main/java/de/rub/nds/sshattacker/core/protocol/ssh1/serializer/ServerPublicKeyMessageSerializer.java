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
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.ServerPublicKeyMessage;
import java.util.zip.CRC32;
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
        byte[] flags = new byte[4];
        appendBytes(flags);
        LOGGER.debug("Flags:  " + ArrayConverter.bytesToRawHexString(flags));
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
        CRC32 crc = new CRC32();
        crc.update(getAlreadySerialized());
        byte[] checksum = ArrayConverter.longToBytes(crc.getValue(), 4);
        appendBytes(checksum);
        LOGGER.debug("CRC:  " + ArrayConverter.bytesToRawHexString(checksum));
    }

    private void serializeCookie() {
        appendBytes(message.getAntiSpoofingCookie().getValue());
        LOGGER.debug(
                "Host key bytes: "
                        + ArrayConverter.bytesToRawHexString(
                                message.getAntiSpoofingCookie().getValue()));
    }

    private void serializeServerKeyBytes() {
        appendInt(message.getServerKey().getPublicKey().getModulus().bitLength(), 4);

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

        appendInt(message.getHostKey().getPublicKey().getModulus().bitLength(), 4);
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

    @Override
    protected byte[] serializeBytes() {
        super.serializeProtocolMessageContents();
        LOGGER.debug(
                "[bro] SSHV1 serializied PubKey Message. Content: {}",
                ArrayConverter.bytesToHexString(getAlreadySerialized()));
        return getAlreadySerialized();
    }
}
