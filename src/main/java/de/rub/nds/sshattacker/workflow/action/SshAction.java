package de.rub.nds.sshattacker.workflow.action;

import de.rub.nds.sshattacker.transport.Aliasable;
import de.rub.nds.sshattacker.exceptions.ConfigurationException;
import de.rub.nds.sshattacker.exceptions.WorkflowExecutionException;
import de.rub.nds.sshattacker.state.State;
import java.io.Serializable;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlTransient;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlAccessorType(XmlAccessType.FIELD)
public abstract class SshAction implements Serializable, Aliasable {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final boolean EXECUTED_DEFAULT = false;

    private Boolean executed = null;

    // Whether the action is executed in a workflow with a single connection
    // or not. Useful to decide which information can be stripped in filter().
    @XmlTransient
    private Boolean singleConnectionWorkflow = true;

    @XmlTransient
    private final Set<String> aliases = new LinkedHashSet<>();
    
    public SshAction(){
    }
    
        public boolean isExecuted() {
        if (executed == null) {
            return EXECUTED_DEFAULT;
        }
        return executed;
    }

    public void setExecuted(Boolean executed) {
        this.executed = executed;
    }

    public Boolean isSingleConnectionWorkflow() {
        return singleConnectionWorkflow;
    }

    public void setSingleConnectionWorkflow(Boolean singleConnectionWorkflow) {
        this.singleConnectionWorkflow = singleConnectionWorkflow;
    }
    
    public abstract void execute(State state) throws WorkflowExecutionException;

    public abstract void reset();

    /**
     * Add default values and initialize empty fields.
     */
    public void normalize() {
        // We don't need any defaults
    }

    /**
     * Add default values from given defaultAction and initialize empty fields.
     *
     * @param defaultAction
     *            Not needed / not evaluated
     */
    public void normalize(SshAction defaultAction) {
        // We don't need any defaults
    }

    /**
     * Filter empty fields and default values.
     */
    public void filter() {
    }

    /**
     * Filter empty fields and default values given in defaultAction.
     *
     * @param defaultAction
     *            Not needed / not evaluated
     */
    public void filter(SshAction defaultAction) {
    }

    @Override
    public String getFirstAlias() {
        return getAllAliases().iterator().next();
    }

    @Override
    public boolean containsAllAliases(Collection<String> aliases) {
        return getAllAliases().containsAll(aliases);
    }

    ;

    @Override
    public boolean containsAlias(String alias) {
        return getAllAliases().contains(alias);
    }

    ;

    @Override
    public void assertAliasesSetProperly() throws ConfigurationException {
    }

    @Override
    public Set<String> getAllAliases() {
        return aliases;
    }

    /**
     * Check that the Action got executed as planned.
     *
     * @return True if the Action executed as planned
     */
    public abstract boolean executedAsPlanned();

    public boolean isMessageAction() {
        return this instanceof MessageAction;
    }

    @Override
    public String aliasesToString() {
        StringBuilder sb = new StringBuilder();
        for (String alias : getAllAliases()) {
            sb.append(alias).append(",");
        }
        sb.deleteCharAt(sb.lastIndexOf(","));
        return sb.toString();
    }

    public String toCompactString() {
        StringBuilder sb = new StringBuilder();
        sb.append(this.getClass().getSimpleName());
        if (!getAllAliases().isEmpty()) {
            sb.append(" [").append(aliasesToString()).append("]");
        }
        return sb.toString();
    }
}
