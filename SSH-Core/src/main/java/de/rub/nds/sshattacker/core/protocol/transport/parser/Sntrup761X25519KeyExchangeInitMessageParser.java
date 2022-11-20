/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.core.constants.CryptoConstants;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.HybridKeyExchangeInitMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Sntrup761X25519KeyExchangeInitMessageParser
        extends SshMessageParser<HybridKeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public Sntrup761X25519KeyExchangeInitMessageParser(byte[] array) {
        super(array);
    }

    public Sntrup761X25519KeyExchangeInitMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    private void parseMultiPrecisionInteger() {
        int length = parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH);
        LOGGER.debug("Total Length: " + length);

        message.setEphemeralSNTRUPPublicKeyLength(length - CryptoConstants.X25519_POINT_SIZE);
        LOGGER.debug(
                "sntrup761 public key (client) length: "
                        + message.getEphemeralSNTRUPPublicKeyLength().getValue());

        message.setEphemeralSNTRUPPublicKey(
                parseByteArrayField(message.getEphemeralSNTRUPPublicKeyLength().getValue()));
        LOGGER.debug(
                "sntrup761 public key (client): "
                        + ArrayConverter.bytesToHexString(
                                message.getEphemeralSNTRUPPublicKey().getValue()));

        message.setEphemeralECPublicKeyLength(length - CryptoConstants.SNTRUP761_PUBLIC_KEY_SIZE);
        LOGGER.debug(
                "c25519 public key (client) length: "
                        + message.getEphemeralECPublicKeyLength().getValue());

        message.setEphemeralECPublicKey(
                parseByteArrayField(message.getEphemeralECPublicKeyLength().getValue()));
        LOGGER.debug(
                "c25519 public key (client): "
                        + ArrayConverter.bytesToHexString(
                                message.getEphemeralECPublicKey().getValue()));
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseMultiPrecisionInteger();
    }

    @Override
    protected HybridKeyExchangeInitMessage createMessage() {
        return new HybridKeyExchangeInitMessage();
    }
}
