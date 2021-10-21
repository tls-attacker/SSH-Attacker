/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelSuccessMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelSuccessMessageSerializer extends ChannelMessageSerializer<ChannelSuccessMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelSuccessMessageSerializer(ChannelSuccessMessage message) {
        super(message);
    }
}