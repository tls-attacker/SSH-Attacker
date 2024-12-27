/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.extension.SftpExtensionUnknown;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpExtensionUnknownSerializer
        extends SftpAbstractExtensionSerializer<SftpExtensionUnknown> {

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    protected void serializeExtensionValue(SftpExtensionUnknown object, SerializerStream output) {
        Integer valueLength = object.getValueLength().getValue();
        LOGGER.debug("Extension value length: {}", valueLength);
        output.appendInt(valueLength, DataFormatConstants.UINT32_SIZE);
        byte[] value = object.getValue().getValue();
        LOGGER.debug("Extension value: {}", () -> ArrayConverter.bytesToRawHexString(value));
        output.appendBytes(value);
    }
}
