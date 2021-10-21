/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeReplyMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhGexKeyExchangeReplyMessageSerializer
        extends SshMessageSerializer<DhGexKeyExchangeReplyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DhGexKeyExchangeReplyMessageSerializer(DhGexKeyExchangeReplyMessage message) {
        super(message);
    }

    private void serializeHostKey() {
        appendInt(message.getHostKeyLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Host key length: " + message.getHostKeyLength().getValue());
        appendBytes(message.getHostKey().getValue());
        LOGGER.debug(
                "Host key: " + ArrayConverter.bytesToRawHexString(message.getHostKey().getValue()));
    }

    private void serializePublicKey() {
        appendInt(
                message.getEphemeralPublicKeyLength().getValue(),
                DataFormatConstants.MPINT_SIZE_LENGTH);
        LOGGER.debug("Public key length: " + message.getEphemeralPublicKeyLength().getValue());
        appendBytes(message.getEphemeralPublicKey().getValue().toByteArray());
        LOGGER.debug("Public key: " + message.getEphemeralPublicKey().getValue());
    }

    private void serializeSignature() {
        appendInt(message.getSignatureLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Signature length: " + message.getSignatureLength().getValue());
        appendBytes(message.getSignature().getValue());
        LOGGER.debug("Signature: " + message.getSignature());
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeHostKey();
        serializePublicKey();
        serializeSignature();
    }
}
