package de.rub.nds.sshattacker.workflow.factory;

import de.rub.nds.sshattacker.config.Config;
import de.rub.nds.sshattacker.constants.RunningModeType;
import de.rub.nds.sshattacker.workflow.WorkflowTrace;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Create a WorkflowTace based on a Config instance.
 */
public class WorkflowConfigurationFactory {

    private static final Logger LOGGER = LogManager.getLogger();

    protected final Config config;
    RunningModeType mode;

    public WorkflowConfigurationFactory(Config config) {
        this.config = config;
    }

    public WorkflowTrace createWorkflowTrace(WorkflowTraceType workflowTraceType, RunningModeType runningMode) {
        return new WorkflowTrace();
    }
}
