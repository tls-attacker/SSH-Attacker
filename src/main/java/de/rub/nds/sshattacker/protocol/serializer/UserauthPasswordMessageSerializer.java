package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.sshattacker.constants.UserauthMethodsConstants;
import de.rub.nds.sshattacker.protocol.message.UserauthPasswordMessage;
import de.rub.nds.sshattacker.util.Converter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserauthPasswordMessageSerializer extends MessageSerializer<UserauthPasswordMessage> {
    
    private final UserauthPasswordMessage msg;
    private static final Logger LOGGER = LogManager.getLogger();

    public UserauthPasswordMessageSerializer(UserauthPasswordMessage msg) {
        super(msg);
        this.msg = msg;
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        LOGGER.debug("username: " + msg.getUsername().getValue());
        appendBytes(Converter.stringToLengthPrefixedString(msg.getUsername().getValue()));
        LOGGER.debug("servicename: " + msg.getServicename().getValue());
        appendBytes(Converter.stringToLengthPrefixedString(msg.getServicename().getValue()));
        appendBytes(Converter.stringToLengthPrefixedString(UserauthMethodsConstants.PASSWORD));
        LOGGER.debug("expectResponse: " + msg.getExpectResponse().getValue());
        appendByte(msg.getExpectResponse().getValue());
        LOGGER.debug("password: " + msg.getPassword().getValue());
        appendBytes(Converter.stringToLengthPrefixedString(msg.getPassword().getValue()));
        return getAlreadySerialized();
    }

}
