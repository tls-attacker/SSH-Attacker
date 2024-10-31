/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.string;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessageParser;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class StringDataMessageParser extends ProtocolMessageParser<StringDataMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public StringDataMessageParser(byte[] array) {
        super(array);
    }

    public StringDataMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public StringDataMessage createMessage() {
        return new StringDataMessage();
    }

    private void parseData() {
        message.setData(parseByteString(getBytesLeft(), StandardCharsets.UTF_8));
        LOGGER.debug("Data: {}", () -> backslashEscapeString(message.getData().getValue()));
    }

    @Override
    protected void parseProtocolMessageContents() {
        parseData();
    }
}
