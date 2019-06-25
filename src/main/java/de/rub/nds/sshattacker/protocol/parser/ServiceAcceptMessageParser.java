package de.rub.nds.sshattacker.protocol.parser;

import de.rub.nds.sshattacker.constants.DataFormatConstants;
import de.rub.nds.sshattacker.protocol.message.ServiceAcceptMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServiceAcceptMessageParser extends MessageParser<ServiceAcceptMessage>{
    private static final Logger LOGGER = LogManager.getLogger();

    public ServiceAcceptMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public ServiceAcceptMessage createMessage() {
        return new ServiceAcceptMessage();
    }

    @Override
    protected void parseMessageSpecificPayload(ServiceAcceptMessage msg) {
        int length = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("serviceName Length: " + length);
        String serviceName = parseByteString(length);
        LOGGER.debug("serviceName: " + serviceName);
        msg.setServiceName(serviceName);
    }

}
