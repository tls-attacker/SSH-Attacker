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

public class WorkflowOutputDelegate extends Delegate {

    @Parameter(
            names = "-workflow_output",
            description =
                    "This parameter allows you to serialize the whole workflow trace into a specific XML file")
    private String workflowOutput = null;

    public WorkflowOutputDelegate() {}

    public String getWorkflowOutput() {
        return workflowOutput;
    }

    public void setWorkflowOutput(String workflowOutput) {
        this.workflowOutput = workflowOutput;
    }

    @Override
    public void applyDelegate(Config config) {
        if (workflowOutput != null) {
            config.setWorkflowOutput(workflowOutput);
        }
    }
}
