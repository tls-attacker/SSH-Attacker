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
import de.rub.nds.sshattacker.core.protocol.transport.message.ServiceAcceptMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServiceAcceptMessageParser extends MessageParser<ServiceAcceptMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ServiceAcceptMessageParser(int startPosition, byte[] array) {
        super(startPosition, array);
    }

    private void parseServiceType(ServiceAcceptMessage msg) {
        msg.setServiceNameLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Service name length: " + msg.getServiceNameLength());
        msg.setServiceName(
                parseByteString(msg.getServiceNameLength().getValue(), StandardCharsets.US_ASCII));
        LOGGER.debug("Service name: " + msg.getServiceName());
    }

    @Override
    protected void parseMessageSpecificPayload(ServiceAcceptMessage msg) {
        parseServiceType(msg);
    }

    @Override
    public ServiceAcceptMessage createMessage() {
        return new ServiceAcceptMessage();
    }
}
