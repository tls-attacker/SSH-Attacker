/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.constants.ChannelRequestType;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestPtyMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelRequestPtyMessagePreparator
        extends ChannelRequestMessagePreparator<ChannelRequestPtyMessage> {

    public ChannelRequestPtyMessagePreparator() {
        super(ChannelRequestType.PTY_REQ, true);
    }

    @Override
    public void prepareChannelRequestMessageSpecificContents(
            ChannelRequestPtyMessage object, Chooser chooser) {
        Config config = chooser.getConfig();
        object.setTermEnvVariable(config.getDefaultTermEnvVariable(), true);
        object.setWidthCharacters(config.getDefaultTerminalWidthColumns());
        object.setHeightRows(config.getDefaultTerminalHeightRows());
        object.setWidthPixels(config.getDefaultTerminalWidthPixels());
        object.setHeightPixels(config.getDefaultTerminalHeightPixels());
        object.setEncodedTerminalModes(new byte[0], true);
    }
}
