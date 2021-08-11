/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.MessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.ServiceRequestMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServiceRequestMessageParser extends MessageParser<ServiceRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ServiceRequestMessageParser(int startPosition, byte[] array) {
        super(startPosition, array);
    }

    private void parseServiceName(ServiceRequestMessage msg) {
        msg.setServiceNameLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Service name length: " + msg.getServiceNameLength().getValue());
        msg.setServiceName(
                parseByteString(msg.getServiceNameLength().getValue(), StandardCharsets.US_ASCII));
        LOGGER.debug("Service name: " + msg.getServiceName().getValue());
    }

    @Override
    protected void parseMessageSpecificPayload(ServiceRequestMessage msg) {
        parseServiceName(msg);
    }

    @Override
    public ServiceRequestMessage createMessage() {
        return new ServiceRequestMessage();
    }
}
