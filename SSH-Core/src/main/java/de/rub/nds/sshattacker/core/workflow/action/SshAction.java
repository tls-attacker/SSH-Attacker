/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.action;

import de.rub.nds.sshattacker.core.connection.Aliasable;
import de.rub.nds.sshattacker.core.exceptions.ConfigurationException;
import de.rub.nds.sshattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.sshattacker.core.layer.LayerConfiguration;
import de.rub.nds.sshattacker.core.layer.LayerStack;
import de.rub.nds.sshattacker.core.layer.SpecificReceiveLayerConfiguration;
import de.rub.nds.sshattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.sshattacker.core.layer.constant.LayerType;
import de.rub.nds.sshattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlTransient;
import java.io.Serializable;
import java.util.*;

@XmlAccessorType(XmlAccessType.FIELD)
public abstract class SshAction implements Serializable, Aliasable {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final boolean EXECUTED_DEFAULT = false;

    private Boolean executed;

    // Whether the action is executed in a workflow with a single connection
    // or not. Useful to decide which information can be stripped in filter().
    @XmlTransient private Boolean singleConnectionWorkflow = true;

    @XmlTransient private final Set<String> aliases = new LinkedHashSet<>();

    public SshAction() {}

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

    /** Add default values and initialize empty fields. */
    @SuppressWarnings("NoopMethodInAbstractClass")
    public void normalize() {
        // We don't need any defaults
    }

    /**
     * Add default values from given defaultAction and initialize empty fields.
     *
     * @param defaultAction Not needed / not evaluated
     */
    @SuppressWarnings("NoopMethodInAbstractClass")
    public void normalize(SshAction defaultAction) {
        // We don't need any defaults
    }

    /** Filter empty fields and default values. */
    @SuppressWarnings("NoopMethodInAbstractClass")
    public void filter() {}

    /**
     * Filter empty fields and default values given in defaultAction.
     *
     * @param defaultAction Not needed / not evaluated
     */
    @SuppressWarnings("NoopMethodInAbstractClass")
    public void filter(SshAction defaultAction) {}

    @Override
    public String getFirstAlias() {
        return getAllAliases().iterator().next();
    }

    @Override
    public boolean containsAllAliases(Collection<String> aliases) {
        return getAllAliases().containsAll(aliases);
    }

    @Override
    public boolean containsAlias(String alias) {
        return getAllAliases().contains(alias);
    }

    @SuppressWarnings("NoopMethodInAbstractClass")
    @Override
    public void assertAliasesSetProperly() throws ConfigurationException {}

    @SuppressWarnings("SuspiciousGetterSetter")
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
        sb.append(getClass().getSimpleName());
        if (!getAllAliases().isEmpty()) {
            sb.append(" [").append(aliasesToString()).append("]");
        }
        return sb.toString();
    }

    public List<LayerConfiguration> sortLayerConfigurations(
            LayerStack layerStack, LayerConfiguration... unsortedLayerConfigurations) {
        return sortLayerConfigurations(
                layerStack, new LinkedList<>(Arrays.asList(unsortedLayerConfigurations)));
    }

    public List<LayerConfiguration> sortLayerConfigurations(
            LayerStack layerStack, List<LayerConfiguration> unsortedLayerConfigurations) {
        List<LayerConfiguration> sortedLayerConfigurations = new LinkedList<>();
        // iterate over all layers in the stack and assign the correct configuration
        // reset configurations to only assign a configuration to the upper most layer
        for (LayerType layerType : layerStack.getLayersInStack()) {
            ImplementedLayers layer;
            try {
                layer = (ImplementedLayers) layerType;
            } catch (ClassCastException e) {
                LOGGER.warn(
                        "Cannot assign layer "
                                + layerType.getName()
                                + "to current LayerStack. LayerType not implemented for SSHAction.");
                continue;
            }
            Optional<LayerConfiguration> layerConfiguration = Optional.empty();
            if (layer == ImplementedLayers.SSHV1 || layer == ImplementedLayers.SSHV2) {
                layerConfiguration =
                        unsortedLayerConfigurations.stream()
                                .filter(layerConfig -> layerConfig.getLayerType().equals(layer))
                                .findFirst();
            }
            if (layerConfiguration.isPresent()) {
                sortedLayerConfigurations.add(layerConfiguration.get());
                unsortedLayerConfigurations.remove(layerConfiguration.get());
            } else {
                sortedLayerConfigurations.add(
                        new SpecificReceiveLayerConfiguration(layerType, new LinkedList<>()));
            }
        }
        return sortedLayerConfigurations;
    }
}
