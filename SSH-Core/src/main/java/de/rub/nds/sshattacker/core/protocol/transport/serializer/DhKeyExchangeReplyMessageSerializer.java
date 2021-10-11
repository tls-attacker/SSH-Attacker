/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.MessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhKeyExchangeReplyMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhKeyExchangeReplyMessageSerializer
        extends MessageSerializer<DhKeyExchangeReplyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DhKeyExchangeReplyMessageSerializer(DhKeyExchangeReplyMessage msg) {
        super(msg);
    }

    private void serializeHostKey(DhKeyExchangeReplyMessage msg) {
        appendInt(msg.getHostKeyLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Host key length: " + msg.getHostKeyLength().getValue());
        appendBytes(msg.getHostKey().getValue());
        LOGGER.debug(
                "Host key: " + ArrayConverter.bytesToRawHexString(msg.getHostKey().getValue()));
    }

    private void serializePublicKey(DhKeyExchangeReplyMessage msg) {
        appendInt(
                msg.getEphemeralPublicKeyLength().getValue(),
                DataFormatConstants.MPINT_SIZE_LENGTH);
        LOGGER.debug("Public key length: " + msg.getEphemeralPublicKeyLength().getValue());
        appendBytes(msg.getEphemeralPublicKey().getValue().toByteArray());
        LOGGER.debug("Public key: " + msg.getEphemeralPublicKey().getValue());
    }

    private void serializeSignature(DhKeyExchangeReplyMessage msg) {
        appendInt(msg.getSignatureLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Signature length: " + msg.getSignatureLength().getValue());
        appendBytes(msg.getSignature().getValue());
        LOGGER.debug("Signature: " + msg.getSignature());
    }

    @Override
    public void serializeMessageSpecificPayload() {
        serializeHostKey(msg);
        serializePublicKey(msg);
        serializeSignature(msg);
    }
}
