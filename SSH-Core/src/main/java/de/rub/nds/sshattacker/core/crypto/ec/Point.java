/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.ec;

import de.rub.nds.sshattacker.core.constants.NamedEcGroup;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElements;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.Objects;

/**
 * Can be used to store a point of an elliptic curve.
 *
 * <p>Affine points store their x and y coordinates. The projective z-coordinate (equal to 1) will
 * not be stored. The point at infinity [0:1:0] (the only point with z-coordinate 0) does not store
 * any of its coordinates.
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Point implements Serializable {
    public static Point createPoint(BigInteger x, BigInteger y, NamedEcGroup group) {
        EllipticCurve curve = CurveFactory.getCurve(group);
        return curve.getPoint(x, y);
    }

    /*
     * Point objects are immutable. This should make deep copies in the methods
     * of the EllipticCurve class unnecessary.
     */
    @XmlElements({
        @XmlElement(type = FieldElementF2m.class, name = "xFieldElementF2m"),
        @XmlElement(type = FieldElementFp.class, name = "xFieldElementFp")
    })
    private final FieldElement fieldX;

    @XmlElements({
        @XmlElement(type = FieldElementF2m.class, name = "yFieldElementF2m"),
        @XmlElement(type = FieldElementFp.class, name = "yFieldElementFp")
    })
    private final FieldElement fieldY;

    private final boolean atInfinity;

    /** Instantiates the point at infinity. */
    public Point() {
        super();
        atInfinity = true;
        fieldX = null;
        fieldY = null;
    }

    /**
     * Instantiates an affine point with coordinates x and y. Calling EllipticCurve.getPoint()
     * should always be preferred over using this constructor.
     *
     * @param x A FieldElement representing the x-coordinate of the point.
     * @param y A FieldElement representing the y-coordinate of the point. x and y must be elements
     *     of the same field.
     */
    public Point(FieldElement x, FieldElement y) {
        super();
        fieldX = x;
        fieldY = y;
        atInfinity = false;
    }

    /**
     * Checks whether the point is the point at infinity.
     *
     * @return True if point is the point at infinity, false otherwise.
     */
    public boolean isAtInfinity() {
        return atInfinity;
    }

    public FieldElement getFieldX() {
        return fieldX;
    }

    public FieldElement getFieldY() {
        return fieldY;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        Point point = (Point) obj;
        return atInfinity == point.atInfinity
                && Objects.equals(fieldX, point.fieldX)
                && Objects.equals(fieldY, point.fieldY);
    }

    @Override
    public int hashCode() {
        return Objects.hash(fieldX, fieldY, atInfinity);
    }

    @Override
    public String toString() {
        if (atInfinity) {
            return "Point: Infinity";
        } else {
            return "Point: (" + fieldX + ", " + fieldY + ")";
        }
    }
}
