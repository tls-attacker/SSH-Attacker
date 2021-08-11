/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.MessageSerializer;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestMessage;
import de.rub.nds.sshattacker.core.util.Converter;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class GlobalRequestMessageSerializer<T extends GlobalRequestMessage<T>>
        extends MessageSerializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    public GlobalRequestMessageSerializer(T msg) {
        super(msg);
    }

    private void serializeRequestName() {
        LOGGER.debug("Request name length: " + msg.getRequestNameLength().getValue());
        appendInt(msg.getRequestNameLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Request name: " + msg.getRequestName().getValue());
        appendString(msg.getRequestName().getValue(), StandardCharsets.US_ASCII);
    }

    private void serializeWantReply() {
        LOGGER.debug("Want reply: " + Converter.byteToBoolean(msg.getWantReply().getValue()));
        appendByte(msg.getWantReply().getValue());
    }

    @Override
    protected void serializeMessageSpecificPayload() {
        serializeRequestName();
        serializeWantReply();
    }
}
