/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.ChannelRequestType;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestX11ReqMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelRequestX11ReqMessagePreparator
        extends ChannelRequestMessagePreparator<ChannelRequestX11ReqMessage> {

    public ChannelRequestX11ReqMessagePreparator(
            Chooser chooser, ChannelRequestX11ReqMessage message) {
        super(chooser, message, ChannelRequestType.X11_REQ, true);
    }

    @Override
    public void prepareChannelRequestMessageSpecificContents() {
        getObject().setSingleConnection(true);
        getObject().setX11AuthenticationProtocol("", true);
        getObject().setX11AuthenticationCookie("", true);
        getObject().setX11ScreenNumber(1);
    }
}
