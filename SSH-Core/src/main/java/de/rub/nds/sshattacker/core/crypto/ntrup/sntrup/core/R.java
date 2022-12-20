/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core;

import cc.redberry.rings.Rings;
import cc.redberry.rings.poly.UnivariateRing;
import cc.redberry.rings.poly.univar.UnivariateDivision;
import cc.redberry.rings.poly.univar.UnivariatePolynomialZ64;
import cc.redberry.rings.poly.univar.UnivariatePolynomialZp64;
import java.util.stream.LongStream;

public class R {

    private SntrupParameterSet set;
    private UnivariatePolynomialZ64 r;
    private UnivariatePolynomialZ64 mod;

    public R(SntrupParameterSet set, long[] coefficient) {
        this.set = set;
        this.mod = genereateMod(set);
        this.r =
                UnivariateDivision.remainder(
                        UnivariatePolynomialZ64.create(coefficient), mod, false);
    }

    private UnivariatePolynomialZ64 genereateMod(SntrupParameterSet set) {
        return UnivariatePolynomialZ64.parse("x^" + set.getP() + "-x-1");
    }

    private R(SntrupParameterSet set, UnivariatePolynomialZ64 r) {
        this.set = set;
        this.r = r;
        this.mod = genereateMod(set);
    }

    public SntrupParameterSet getSet() {
        return set;
    }

    public UnivariatePolynomialZ64 getR() {
        return r.clone();
    }

    public void setR(long[] coefficient) {
        this.r =
                UnivariateDivision.remainder(
                        UnivariatePolynomialZ64.create(coefficient), mod, false);
    }

    public UnivariatePolynomialZ64 getMod() {
        return mod.clone();
    }

    public LongStream stream() {
        return r.stream();
    }

    public static R randomSmall(SntrupParameterSet set) {
        UnivariateRing<UnivariatePolynomialZp64> z3 = Rings.UnivariateRingZp64(3);
        R3 tmp = new R3(set, z3.randomElement().stream().toArray());
        return lift(tmp);
    }

    public static R lift(R3 r3) {
        return new R(r3.getSet(), r3.stream().toArray());
    }

    public static R multiply(Short shrt, R r) {
        R convertedShort = new R(shrt.getSet(), shrt.stream().toArray());
        return multiply(convertedShort, r);
    }

    public static R multiply(R r1, R r2) {
        return new R(
                r1.set,
                UnivariateDivision.remainder(r1.getR().multiply(r2.getR()), r1.getMod(), true));
    }

    @Override
    public String toString() {
        return r.toString();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((r == null) ? 0 : r.hashCode());
        result = prime * result + ((set == null) ? 0 : set.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null) return false;
        if (getClass() != obj.getClass()) return false;
        R other = (R) obj;
        if (r == null) {
            if (other.r != null) return false;
        } else if (!r.equals(other.r)) return false;
        if (set != other.set) return false;
        return true;
    }
}
