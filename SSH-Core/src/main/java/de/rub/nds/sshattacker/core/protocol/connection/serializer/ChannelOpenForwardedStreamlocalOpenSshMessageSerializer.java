/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenForwardedStreamlocalOpenSshMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelOpenForwardedStreamlocalOpenSshMessageSerializer
        extends ChannelOpenMessageSerializer<ChannelOpenForwardedStreamlocalOpenSshMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeSocketPath(
            ChannelOpenForwardedStreamlocalOpenSshMessage object, SerializerStream output) {
        LOGGER.debug("Socket path length: {}", object.getSocketPathLength().getValue());
        output.appendInt(object.getSocketPathLength().getValue());
        LOGGER.debug("Socket path: {}", object.getSocketPath().getValue());
        output.appendString(object.getSocketPath().getValue(), StandardCharsets.US_ASCII);
    }

    private static void serializeReserved(
            ChannelOpenForwardedStreamlocalOpenSshMessage object, SerializerStream output) {
        LOGGER.debug("Reserved length: {}", object.getReservedLength().getValue());
        output.appendInt(object.getReservedLength().getValue());
        LOGGER.debug(
                "Reserved: {}",
                ArrayConverter.bytesToRawHexString(object.getReserved().getValue()));
        output.appendBytes(object.getReserved().getValue());
    }

    @Override
    protected void serializeMessageSpecificContents(
            ChannelOpenForwardedStreamlocalOpenSshMessage object, SerializerStream output) {
        super.serializeMessageSpecificContents(object, output);
        serializeSocketPath(object, output);
        serializeReserved(object, output);
    }
}
