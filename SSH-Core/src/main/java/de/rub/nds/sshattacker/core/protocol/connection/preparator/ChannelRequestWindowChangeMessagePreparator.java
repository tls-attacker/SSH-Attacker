/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.ChannelRequestType;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestWindowChangeMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelRequestWindowChangeMessagePreparator
        extends ChannelRequestMessagePreparator<ChannelRequestWindowChangeMessage> {

    public ChannelRequestWindowChangeMessagePreparator(
            Chooser chooser, ChannelRequestWindowChangeMessage message) {
        super(chooser, message, ChannelRequestType.WINDOW_CHANGE, false);
    }

    @Override
    public void prepareChannelRequestMessageSpecificContents() {
        getObject().setWidthColumns(chooser.getConfig().getDefaultTerminalWidthColumns());
        getObject().setHeightRows(chooser.getConfig().getDefaultTerminalHeightRows());
        getObject().setWidthPixels(chooser.getConfig().getDefaultTerminalWidthPixels());
        getObject().setHeightPixels(chooser.getConfig().getDefaultTerminalHeightPixels());
    }
}
