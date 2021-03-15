package de.rub.nds.sshattacker.protocol.parser;

import de.rub.nds.sshattacker.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.protocol.message.ServiceRequestMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServiceRequestMessageParser extends MessageParser<ServiceRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ServiceRequestMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public ServiceRequestMessage createMessage() {
        return new ServiceRequestMessage();
    }

    @Override
    protected void parseMessageSpecificPayload(ServiceRequestMessage msg) {
        int length = parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH);
        LOGGER.debug("serviceName Length: " + length);
        String serviceName = parseByteString(length);
        LOGGER.debug("serviceName: " + serviceName);
        msg.setServiceName(serviceName);
    }

}
