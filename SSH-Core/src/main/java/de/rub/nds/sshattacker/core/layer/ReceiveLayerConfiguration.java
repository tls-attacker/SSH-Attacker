/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.layer;

import de.rub.nds.sshattacker.core.layer.constant.LayerType;
import de.rub.nds.sshattacker.core.layer.data.DataContainer;
import java.util.List;

/**
 * Abstracts different ReceiveConfigurations. A ReceiveLayerConfiguration always specifies a list of
 * containers the layer should receive.
 *
 * @param <Container>
 */
public abstract class ReceiveLayerConfiguration<Container extends DataContainer>
        extends LayerConfiguration<Container> {

    public ReceiveLayerConfiguration(LayerType layerType, List<Container> containerList) {
        super(layerType, containerList);
    }

    public ReceiveLayerConfiguration(LayerType layerType, Container... containers) {
        super(layerType, containers);
    }

    public abstract boolean isProcessTrailingContainers();
}
