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
import de.rub.nds.sshattacker.core.protocol.ssh1.message.ClientSessionKeyMessage;
import java.math.BigInteger;
import java.util.zip.CRC32;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ClientSessionKeyMessageSerializer
        extends SshMessageSerializer<ClientSessionKeyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();
    private HybridKeyExchangeCombiner combiner;

    public ClientSessionKeyMessageSerializer(
            ClientSessionKeyMessage message, HybridKeyExchangeCombiner combiner) {
        super(message);
        this.combiner = combiner;
    }

    private void serializieCipherType() {
        int cipherType = message.getChosenCipherMethod().getId();
        appendInt(cipherType, 1);
        LOGGER.debug("CipherType:  {}", cipherType);
    }

    private void serializeCookie() {
        appendBytes(message.getAntiSpoofingCookie().getValue());
        LOGGER.debug(
                "AntiSpoofingCookie: "
                        + ArrayConverter.bytesToRawHexString(
                                message.getAntiSpoofingCookie().getValue()));
    }

    private void serializeSessionKey() {
        // appendMultiPrecisionAsByteArray(message.getEncryptedSessioKey().getValue());
        appendMultiPrecision(new BigInteger(1, message.getEncryptedSessioKey().getValue()));
        LOGGER.debug(
                "Session Key: "
                        + ArrayConverter.bytesToRawHexString(
                                message.getEncryptedSessioKey().getValue()));
    }

    private void serializeProtocolFlags() {
        int flags = message.getProtocolFlagMask().getValue();
        appendInt(flags, 4);
        LOGGER.debug("Flags:  " + Integer.toBinaryString(flags));
    }

    private void serializCRCChecksum() {
        CRC32 crc = new CRC32();
        crc.update(getAlreadySerialized());
        byte[] checksum = ArrayConverter.longToBytes(crc.getValue(), 4);
        appendBytes(checksum);
        LOGGER.debug("CRC:  " + ArrayConverter.bytesToRawHexString(checksum));
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializieCipherType();
        serializeCookie();
        serializeSessionKey();
        serializeProtocolFlags();
        serializCRCChecksum();
    }
}
