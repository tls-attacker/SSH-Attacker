package de.rub.nds.sshattacker.workflow.executor;

import de.rub.nds.sshattacker.config.Config;
import de.rub.nds.sshattacker.exceptions.WorkflowExecutionException;
import de.rub.nds.sshattacker.state.State;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class WorkflowExecutor {

//    static {
//        if (!BouncyCastleProviderChecker.isLoaded()) {
//            throw new BouncyCastleNotLoadedException("BouncyCastleProvider not loaded");
//        }
//    }
    private static final Logger LOGGER = LogManager.getLogger();

    protected final WorkflowExecutorType type;

    protected final State state;
    protected final Config config;

    /**
     * Prepare a workflow trace for execution according to the given state and
     * executor type. Try various ways to initialize a workflow trace and add it
     * to the state. For workflow creation, use the first method which does not
     * return null, in the following order: state.getWorkflowTrace(),
     * state.config.getWorkflowInput(), config.getWorkflowTraceType().
     *
     * @param type of the workflow executor (currently only DEFAULT)
     * @param state to work on
     */
    public WorkflowExecutor(WorkflowExecutorType type, State state) {
        this.type = type;
        this.state = state;
        this.config = state.getConfig();
    }

    public abstract void executeWorkflow() throws WorkflowExecutionException;

}
