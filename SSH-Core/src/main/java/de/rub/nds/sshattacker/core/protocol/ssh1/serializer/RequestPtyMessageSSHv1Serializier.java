/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.RequestPtyMessageSSH1;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RequestPtyMessageSSHv1Serializier extends SshMessageSerializer<RequestPtyMessageSSH1> {

    private static final Logger LOGGER = LogManager.getLogger();

    public RequestPtyMessageSSHv1Serializier(RequestPtyMessageSSH1 message) {
        super(message);
    }

    private void serializeData() {
        appendInt(
                message.getTermEnvironment().getValue().length(), DataFormatConstants.UINT32_SIZE);
        appendString(message.getTermEnvironment().getValue(), StandardCharsets.UTF_8);
        appendInt(message.getHightRows().getValue(), DataFormatConstants.UINT32_SIZE);
        appendInt(message.getWidthColumns().getValue(), DataFormatConstants.UINT32_SIZE);
        appendInt(message.getWidthPixel().getValue(), DataFormatConstants.UINT32_SIZE);
        appendInt(message.getHightPixel().getValue(), DataFormatConstants.UINT32_SIZE);
        appendInt(message.getTtyModes().getValue(), DataFormatConstants.UINT32_SIZE);
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeData();
    }
}
