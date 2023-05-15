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
import de.rub.nds.sshattacker.core.config.converter.RunningModeConverter;
import de.rub.nds.sshattacker.core.constants.RunningModeType;

public class RunningModeDelegate extends Delegate {

    @Parameter(
            names = "-running_mode",
            description = "The mode for which the workflow trace should be prepared",
            converter = RunningModeConverter.class)
    private RunningModeType runningMode = RunningModeType.CLIENT;

    public RunningModeType getRunningMode() {
        return runningMode;
    }

    public void setRunningMode(RunningModeType runningMode) {
        this.runningMode = runningMode;
    }

    @Override
    public void applyDelegate(Config config) {
        config.setDefaultRunningMode(runningMode);
    }
}
