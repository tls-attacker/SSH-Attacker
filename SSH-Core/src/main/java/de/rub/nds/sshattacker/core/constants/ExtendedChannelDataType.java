/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

public enum ExtendedChannelDataType {
    /*
     * Sources:
     *  - https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#ssh-parameters-7
     */
    // [ RFC 4254 ]
    SSH_EXTENDED_DATA_STDERR(1);

    private final int dataTypeCode;

    ExtendedChannelDataType(@SuppressWarnings("SameParameterValue") int dataTypeCode) {
        this.dataTypeCode = dataTypeCode;
    }

    public int getDataTypeCode() {
        return dataTypeCode;
    }

    public static ExtendedChannelDataType fromDataTypeCode(int dataTypeCode) {
        if (dataTypeCode == 1) {
            return SSH_EXTENDED_DATA_STDERR;
        }
        return null;
    }
}
