package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.sshattacker.protocol.message.ServiceAcceptMessage;
import de.rub.nds.sshattacker.util.Converter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServiceAcceptMessageSerializer extends Serializer<ServiceAcceptMessage> {

    private static final Logger LOGGER = LogManager.getLogger();
    private final ServiceAcceptMessage msg;

    public ServiceAcceptMessageSerializer(ServiceAcceptMessage msg) {
        this.msg = msg;
    }

    @Override
    protected byte[] serializeBytes() {
        LOGGER.debug("serviceName: " + msg.getServiceName().getValue());
        appendBytes(Converter.stringToLengthPrefixedString(msg.getServiceName().getValue()));
        return getAlreadySerialized();
    }

}
