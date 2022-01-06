package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.sshattacker.core.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangeDoneMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RsaKeyExchangeDoneMessageParser extends SshMessageParser<RsaKeyExchangeDoneMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public RsaKeyExchangeDoneMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected RsaKeyExchangeDoneMessage createMessage() {
        return new RsaKeyExchangeDoneMessage();
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseSignature();
    }

    private void parseSignature() {
        message.setSignatureLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug(
                "Signature length: " + message.getSignatureLength().getValue());
        message.setSignature(
                parseByteArrayField(message.getSignatureLength().getValue()));
        LOGGER.debug("Signature: " + message.getSignature());
    }
}
