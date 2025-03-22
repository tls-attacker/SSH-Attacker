/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.string;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class StringDataMessageSerializer extends ProtocolMessageSerializer<StringDataMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeData(StringDataMessage object, SerializerStream output) {
        String data = object.getData().getValue();
        LOGGER.debug("Data: {}", () -> backslashEscapeString(data));
        output.appendString(data, StandardCharsets.UTF_8);
    }

    @Override
    public final void serializeProtocolMessageContents(
            StringDataMessage object, SerializerStream output) {
        serializeData(object, output);
    }
}
