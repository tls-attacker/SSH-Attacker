/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.layer.constant;

/**
 * Pre-defined configurations for the Layer Stack. E.g., SSHv1 will Create a Layerstack containing
 * no SSHv2 Layer to the LayerStack. Custom LayerStack have to be created manually.
 */
public enum LayerConfiguration {
    SSHV1,
    SSHV2;
}
