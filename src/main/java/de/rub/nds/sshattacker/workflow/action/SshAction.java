package de.rub.nds.sshattacker.workflow.action;

import de.rub.nds.sshattacker.connection.Aliasable;
import java.io.Serializable;
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
}
