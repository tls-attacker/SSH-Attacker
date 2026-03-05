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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenDirectStreamlocalOpenSshMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelOpenDirectStreamlocalOpenSshMessageSerializer
        extends ChannelOpenMessageSerializer<ChannelOpenDirectStreamlocalOpenSshMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeSocketPath(
            ChannelOpenDirectStreamlocalOpenSshMessage object, SerializerStream output) {
        LOGGER.debug("Socket path length: {}", object.getSocketPathLength().getValue());
        output.appendInt(object.getSocketPathLength().getValue());
        LOGGER.debug("Socket path: {}", object.getSocketPath().getValue());
        output.appendString(object.getSocketPath().getValue(), StandardCharsets.US_ASCII);
    }

    private static void serializeReservedString(
            ChannelOpenDirectStreamlocalOpenSshMessage object, SerializerStream output) {
        LOGGER.debug("Reserved string length: {}", object.getReservedStringLength().getValue());
        output.appendInt(object.getReservedStringLength().getValue());
        LOGGER.debug(
                "Reserved string: {}",
                () -> ArrayConverter.bytesToRawHexString(object.getReservedString().getValue()));
        output.appendBytes(object.getReservedString().getValue());
    }

    private static void serializeReservedUint32(
            ChannelOpenDirectStreamlocalOpenSshMessage object, SerializerStream output) {
        LOGGER.debug("Reserved uint32: {}", object.getReservedUint32().getValue());
        output.appendInt(object.getReservedUint32().getValue());
    }

    @Override
    protected void serializeMessageSpecificContents(
            ChannelOpenDirectStreamlocalOpenSshMessage object, SerializerStream output) {
        super.serializeMessageSpecificContents(object, output);
        serializeSocketPath(object, output);
        serializeReservedString(object, output);
        serializeReservedUint32(object, output);
    }
}
