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

import java.util.Objects;
import java.util.stream.LongStream;

public class R {

    private final SntrupParameterSet set;
    private UnivariatePolynomialZ64 r;
    private final UnivariatePolynomialZ64 mod;

    public R(SntrupParameterSet set, long[] coefficient) {
        super();
        this.set = set;
        mod = genereateMod(set);
        r = UnivariateDivision.remainder(UnivariatePolynomialZ64.create(coefficient), mod, false);
    }

    private static UnivariatePolynomialZ64 genereateMod(SntrupParameterSet set) {
        return UnivariatePolynomialZ64.parse("x^" + set.getP() + "-x-1");
    }

    private R(SntrupParameterSet set, UnivariatePolynomialZ64 r) {
        super();
        this.set = set;
        this.r = r;
        mod = genereateMod(set);
    }

    public SntrupParameterSet getSet() {
        return set;
    }

    public UnivariatePolynomialZ64 getR() {
        return r.clone();
    }

    public void setR(long[] coefficient) {
        r = UnivariateDivision.remainder(UnivariatePolynomialZ64.create(coefficient), mod, false);
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

    public static R multiply(Short shrt, R r2) {
        R convertedShort = new R(shrt.getSet(), shrt.stream().toArray());
        return multiply(convertedShort, r2);
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
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        R r1 = (R) obj;
        return set == r1.set && Objects.equals(r, r1.r);
    }

    @Override
    public int hashCode() {
        return Objects.hash(set, r);
    }
}
