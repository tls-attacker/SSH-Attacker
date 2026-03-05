/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.sshattacker.core.config.Config;

public class ConfigOutputDelegate extends Delegate {

    @Parameter(
            names = "--config-output",
            description =
                    "Write XML representation "
                            + "of the actual config used during execution to this file")
    private String configOutput;

    public String getConfigOutput() {
        return configOutput;
    }

    public void setConfigOutput(String configOutput) {
        this.configOutput = configOutput;
    }

    @Override
    public void applyDelegate(Config config) {
        if (configOutput != null) {
            config.setConfigOutput(configOutput);
        }
    }
}
