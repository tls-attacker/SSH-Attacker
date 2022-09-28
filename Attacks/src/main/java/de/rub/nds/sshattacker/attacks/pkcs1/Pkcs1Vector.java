/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.pkcs1;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.attacks.general.Vector;
import java.util.Arrays;

/**
 * Attack vector for Pkcs1 attacks. The attack vectors can be named and hold plain and encrypted
 * values
 */
public class Pkcs1Vector implements Vector {

    private String name;

    private String shortName;

    private byte[] plainValue;

    private byte[] encryptedValue;

    private Pkcs1Vector() {}

    /**
     * @param name A String that describes the content of this vector
     * @param shortName Short name of the vector
     * @param value Plain value
     */
    public Pkcs1Vector(String name, String shortName, byte[] value) {
        this.name = name;
        this.shortName = shortName;
        this.plainValue = value;
    }

    @Override
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Override
    public String getShortName() {
        return shortName;
    }

    public void setShortName(String shortName) {
        this.shortName = shortName;
    }

    public byte[] getPlainValue() {
        return plainValue;
    }

    public void setPlainValue(byte[] plainValue) {
        this.plainValue = plainValue;
    }

    public byte[] getEncryptedValue() {
        return encryptedValue;
    }

    public void setEncryptedValue(byte[] encryptedValue) {
        this.encryptedValue = encryptedValue;
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 41 * hash + Arrays.hashCode(this.plainValue);
        hash = 41 * hash + Arrays.hashCode(this.encryptedValue);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final Pkcs1Vector other = (Pkcs1Vector) obj;
        if (!Arrays.equals(this.plainValue, other.plainValue)) {
            return false;
        }
        return Arrays.equals(this.encryptedValue, other.encryptedValue);
    }

    @Override
    public String toString() {
        return ""
                + name
                + "{"
                + "plainValue="
                + ArrayConverter.bytesToHexString(plainValue)
                + ", encryptedValue="
                + ArrayConverter.bytesToHexString(encryptedValue)
                + '}';
    }
}
