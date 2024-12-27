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

    public ChannelRequestX11MessagePreparator() {
        super(ChannelRequestType.X11_REQ, true);
    }

    @Override
    public void prepareChannelRequestMessageSpecificContents(
            ChannelRequestX11Message object, Chooser chooser) {
        object.setSoftlySingleConnection(true);

        object.setSoftlyX11AuthenticationProtocol("", true, chooser.getConfig());
        object.setSoftlyX11AuthenticationCookie("", true, chooser.getConfig());
        object.setSoftlyX11ScreenNumber(1);
    }
}
