/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.ChannelRequestType;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestX11Message;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelRequestX11MessagePreparator
        extends ChannelRequestMessagePreparator<ChannelRequestX11Message> {

    public ChannelRequestX11MessagePreparator(Chooser chooser, ChannelRequestX11Message message) {
        super(chooser, message, ChannelRequestType.X11_REQ, true);
    }

    @Override
    public void prepareChannelRequestMessageSpecificContents() {
        object.setSoftlySingleConnection(true);

        object.setSoftlyX11AuthenticationProtocol("", true, config);
        object.setSoftlyX11AuthenticationCookie("", true, config);
        object.setSoftlyX11ScreenNumber(1);
    }
}
