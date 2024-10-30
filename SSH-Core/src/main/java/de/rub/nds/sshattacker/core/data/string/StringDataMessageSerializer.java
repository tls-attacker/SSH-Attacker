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
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class StringDataMessageSerializer extends ProtocolMessageSerializer<StringDataMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public StringDataMessageSerializer(StringDataMessage message) {
        super(message);
    }

    private void serializeData() {
        LOGGER.debug("Data: {}", backslashEscapeString(message.getData().getValue()));
        appendString(message.getData().getValue(), StandardCharsets.UTF_8);
    }

    @Override
    public final void serializeProtocolMessageContents() {
        serializeData();
    }
}
