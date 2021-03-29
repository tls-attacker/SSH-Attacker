package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.sshattacker.protocol.message.ServiceRequestMessage;
import de.rub.nds.sshattacker.util.Converter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServiceRequestMessageSerializer extends MessageSerializer<ServiceRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();
    private final ServiceRequestMessage msg;

    public ServiceRequestMessageSerializer(ServiceRequestMessage msg) {
        super(msg);
        this.msg = msg;
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        LOGGER.debug("serviceName: " + msg.getServiceName().getValue());
        appendBytes(Converter.stringToLengthPrefixedBinaryString(msg.getServiceName().getValue()));
        return getAlreadySerialized();
    }

}
