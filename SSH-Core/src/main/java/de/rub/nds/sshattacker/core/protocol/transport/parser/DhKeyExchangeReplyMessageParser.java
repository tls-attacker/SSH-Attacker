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
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhKeyExchangeReplyMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhKeyExchangeReplyMessageParser extends SshMessageParser<DhKeyExchangeReplyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /*
        public DhKeyExchangeReplyMessageParser(byte[] array) {
            super(array);
        }
        public DhKeyExchangeReplyMessageParser(byte[] array, int startPosition) {
            super(array, startPosition);
        }
    */

    public DhKeyExchangeReplyMessageParser(InputStream stream) {
        super(stream);
    }

    @Override
    public DhKeyExchangeReplyMessage createMessage() {
        return new DhKeyExchangeReplyMessage();
    }

    private void parseHostKeyBytes() {
        message.setHostKeyBytesLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("Host key bytes length: " + message.getHostKeyBytesLength().getValue());
        message.setHostKeyBytes(parseByteArrayField(message.getHostKeyBytesLength().getValue()));
        LOGGER.debug(
                "Host key bytes: "
                        + ArrayConverter.bytesToRawHexString(message.getHostKeyBytes().getValue()));
    }

    private void parseEphemeralPublicKey() {
        message.setEphemeralPublicKeyLength(
                parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug(
                "Ephemeral public key (server) length: "
                        + message.getEphemeralPublicKeyLength().getValue());
        message.setEphemeralPublicKey(
                parseBigIntField(message.getEphemeralPublicKeyLength().getValue()));
        LOGGER.debug("Ephemeral public key (server): " + message.getEphemeralPublicKey());
    }

    private void parseSignature() {
        message.setSignatureLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("Signature length: " + message.getSignatureLength().getValue());
        message.setSignature(parseByteArrayField(message.getSignatureLength().getValue()));
        LOGGER.debug("Signature: " + message.getSignature());
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseHostKeyBytes();
        parseEphemeralPublicKey();
        parseSignature();
    }

    @Override
    public void parse(DhKeyExchangeReplyMessage message) {
        parseMessageSpecificContents();
    }
}
