/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.ec;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Objects;

/**
 * Can be used to store elements of a galois field.<br>
 * The attribute data should contain some BigInteger representing the element.<br>
 * The attribute modulus should contain some BigInteger that may be used to identify the field (and
 * for calculations).<br>
 * All arithmetic operations are performed within the laws of the specified field.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public abstract class FieldElement implements Serializable {

    /*
     * FieldElement objects are immutable. This should make deep copies in the
     * methods of the EllipticCurve class unnecessary.
     */
    private final BigInteger data;
    private final BigInteger modulus;

    protected FieldElement(BigInteger data, BigInteger modulus) {
        super();
        this.data = data;
        this.modulus = modulus;
    }

    /**
     * Performs an addition in the field, which this is an element of.
     *
     * @param element An element of the field, which this is an element of.
     * @return this + element
     */
    public abstract FieldElement add(FieldElement element);

    /**
     * Performs a subtraction in the field, which this is an element of.
     *
     * @param element An element of the field, which this is an element of.
     * @return this - element
     */
    public FieldElement subtract(FieldElement element) {
        element = element.addInv();
        return add(element);
    }

    /**
     * Performs a multiplication in the field, which this is an element of.
     *
     * @param element An element of the field, which this is an element of.
     * @return this * element
     */
    public abstract FieldElement mult(FieldElement element);

    /**
     * Performs a multiplication with the inverse element of element in the field, which this is an
     * element of.
     *
     * @param element An element of the field, which this is an element of.
     * @return this * element^-1
     */
    public FieldElement divide(FieldElement element) {
        element = element.multInv();
        return mult(element);
    }

    /**
     * Computes the additive inverse element of this.
     *
     * @return -this
     */
    public abstract FieldElement addInv();

    /**
     * Computes the multiplicative inverse element of this.
     *
     * @return this^-1
     */
    public abstract FieldElement multInv();

    public BigInteger getData() {
        return data;
    }

    public BigInteger getModulus() {
        return modulus;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        FieldElement that = (FieldElement) obj;
        return Objects.equals(data, that.data) && Objects.equals(modulus, that.modulus);
    }

    @Override
    public int hashCode() {
        return Objects.hash(data, modulus);
    }

    @Override
    public String toString() {
        return data.toString() + " mod " + modulus.toString();
    }
}
