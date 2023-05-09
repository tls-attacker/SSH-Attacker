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

public class WorkflowInputDelegate extends Delegate {

    @Parameter(
            names = "-workflow_input",
            description =
                    "This parameter allows you to load the whole workflow trace from the specified XML configuration file")
    private String workflowInput;

    public String getWorkflowInput() {
        return workflowInput;
    }

    public void setWorkflowInput(String workflowInput) {
        this.workflowInput = workflowInput;
    }

    @Override
    public void applyDelegate(Config config) {
        if (workflowInput != null) {
            config.setWorkflowInput(workflowInput);
        }
    }
}
