/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.client.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.message.WindowSizeMessageSSH1;

public class WindowSizeMessageSSHv1Serializier
        extends Ssh1MessageSerializer<WindowSizeMessageSSH1> {

    public WindowSizeMessageSSHv1Serializier(WindowSizeMessageSSH1 message) {
        super(message);
    }

    private void serializeData() {
        appendInt(message.getHightRows().getValue(), DataFormatConstants.UINT32_SIZE);
        appendInt(message.getWidthColumns().getValue(), DataFormatConstants.UINT32_SIZE);
        appendInt(message.getWidthPixel().getValue(), DataFormatConstants.UINT32_SIZE);
        appendInt(message.getHightPixel().getValue(), DataFormatConstants.UINT32_SIZE);
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeData();
    }
}
