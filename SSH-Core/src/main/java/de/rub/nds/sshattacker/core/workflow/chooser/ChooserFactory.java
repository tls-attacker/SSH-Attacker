/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.chooser;

import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.constants.ChooserType;
import de.rub.nds.sshattacker.core.exceptions.InvalidChooserTypeException;
import de.rub.nds.sshattacker.core.state.SshContext;

public final class ChooserFactory {
    public static Chooser getChooser(ChooserType type, SshContext context, Config config) {
        if (type == ChooserType.DEFAULT) {
            return new DefaultChooser(context, config);
        }
        throw new InvalidChooserTypeException("ChooserType \"" + type + "\" not supported");
    }

    private ChooserFactory() {
        super();
    }
}
