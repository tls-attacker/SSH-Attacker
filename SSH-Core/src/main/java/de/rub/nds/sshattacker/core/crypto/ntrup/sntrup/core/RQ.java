/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core;

import static org.junit.Assert.*;

import cc.redberry.rings.IntegersZp64;
import cc.redberry.rings.poly.PolynomialMethods;
import cc.redberry.rings.poly.univar.UnivariateDivision;
import cc.redberry.rings.poly.univar.UnivariatePolynomialZp64;

import de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.util.Encoding;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.LongStream;

@SuppressWarnings("StandardVariableNames")
public class RQ {
    private final SntrupParameterSet set;
    private UnivariatePolynomialZp64 rQ;
    private final UnivariatePolynomialZp64 mod;

    public RQ(SntrupParameterSet set, long[] coefficient) {
        super();
        this.set = set;
        mod = genereateMod(set);
        setRQ(coefficient);
    }

    private RQ(SntrupParameterSet set, UnivariatePolynomialZp64 rq) {
        super();
        this.set = set;
        mod = genereateMod(set);
        rQ = rq;
    }

    private static UnivariatePolynomialZp64 genereateMod(SntrupParameterSet set) {
        return UnivariatePolynomialZp64.parse(
                "x^" + set.getP() + "-x-1", new IntegersZp64(set.getQ()), "x");
    }

    public UnivariatePolynomialZp64 getMod() {
        return mod.clone();
    }

    public UnivariatePolynomialZp64 getRQ() {
        return rQ.clone();
    }

    private void setRQ(long[] coefficient) {
        assertTrue(
                "Coefficients have to be between (-(q+1)/2 and (q+1)/2",
                Arrays.stream(coefficient)
                        .filter(c -> c > (set.getQ() + 1) / 2 || c < -(set.getQ() + 1) / 2)
                        .findFirst()
                        .isEmpty());

        rQ =
                UnivariateDivision.remainder(
                        UnivariatePolynomialZp64.create(set.getQ(), coefficient), mod, true);
        assertTrue(rQ.isOverFiniteField());
    }

    public SntrupParameterSet getSet() {
        return set;
    }

    public LongStream stream() {
        return rQ.stream().map(c -> c >= (set.getQ() + 1) / 2 ? c - set.getQ() : c);
    }

    public static RQ invert(RQ rq) {
        UnivariatePolynomialZp64[] xgcd =
                PolynomialMethods.PolynomialExtendedGCD(
                        UnivariatePolynomialZp64.create(rq.set.getQ(), rq.stream().toArray()),
                        genereateMod(rq.set));
        return new RQ(rq.set, xgcd[1]);
    }

    public static RQ multiply(int val, Short shrt) {
        RQ convertedShrt = new RQ(shrt.getSet(), shrt.stream().toArray());
        return multiply(val, convertedShrt);
    }

    public static RQ multiply(int val, RQ rq) {
        return new RQ(
                rq.set, UnivariateDivision.remainder(rq.getRQ().multiply(val), rq.getMod(), true));
    }

    public static RQ multiply(R r, RQ rq2) {
        assert r.getSet() == rq2.set;
        RQ convertedR = new RQ(r.getSet(), r.stream().toArray());
        return multiply(convertedR, rq2);
    }

    public static RQ multiply(RQ rq1, RQ rq2) {
        return new RQ(
                rq1.set,
                UnivariateDivision.remainder(
                        rq1.getRQ().multiply(rq2.getRQ()), rq1.getMod(), true));
    }

    public static RQ multiply(Short shrt, RQ rq2) {
        RQ convertedShrt = new RQ(rq2.set, shrt.stream().toArray());
        return multiply(convertedShrt, rq2);
    }

    public static RQ multiply(Rounded rounded, RQ rq2) {
        RQ convertedRounded = new RQ(rounded.getSet(), rounded.stream().toArray());
        return multiply(convertedRounded, rq2);
    }

    public static RQ sub(Rounded rounded, RQ rq2) {
        RQ convertedRounded = new RQ(rounded.getSet(), rounded.stream().toArray());
        return sub(convertedRounded, rq2);
    }

    public static RQ sub(RQ rq1, RQ rq2) {
        return new RQ(
                rq1.set,
                UnivariateDivision.remainder(
                        rq1.getRQ().subtract(rq2.getRQ()), rq1.getMod(), true));
    }

    public static RQ add(R r, RQ rq2) {
        RQ convertedR = new RQ(r.getSet(), r.stream().toArray());
        return add(convertedR, rq2);
    }

    public static RQ add(RQ rq1, RQ rq2) {
        return new RQ(
                rq1.set,
                UnivariateDivision.remainder(rq1.getRQ().add(rq2.getRQ()), rq1.getMod(), true));
    }

    public byte[] encode() {
        ArrayList<Integer> r =
                rQ.stream()
                        .mapToInt(
                                l ->
                                        Math.toIntExact(
                                                Math.floorMod(
                                                        l + (set.getQ() - 1) / 2, set.getQ())))
                        .boxed()
                        .collect(Collectors.toCollection(ArrayList::new));

        while (r.size() < set.getP()) {
            r.add((set.getQ() + 1) / 2);
        }

        ArrayList<Integer> m =
                IntStream.range(0, r.size())
                        .map(i -> set.getQ())
                        .boxed()
                        .collect(Collectors.toCollection(ArrayList::new));

        assertTrue(r.stream().filter(i -> i < 0).findFirst().isEmpty());
        assertFalse(
                IntStream.range(0, set.getP())
                        .filter(i -> r.get(i) > m.get(i))
                        .findFirst()
                        .isPresent());

        ArrayList<Integer> encdodedCoefficients = Encoding.encode(r, m);

        byte[] res = new byte[encdodedCoefficients.size()];
        for (int i = 0; i < encdodedCoefficients.size(); i++) {
            res[i] = (byte) encdodedCoefficients.get(i).intValue();
        }
        return res;
    }

    public byte[] encode_old() {
        int q12 = (set.getQ() - 1) / 2;
        ArrayList<Integer> h =
                stream()
                        .mapToInt(l -> Math.toIntExact(l + q12))
                        .boxed()
                        .collect(Collectors.toCollection(ArrayList::new));
        for (int i = 0; i < (-set.getP() + set.getP() * 5) % 5; i++) {
            h.add(0);
        }

        return Arrays.copyOfRange(Encoding.seq2byte(h, 6144, 5, 8), 0, 1218);
    }

    public static RQ decode_old(SntrupParameterSet set, byte[] encoded) {
        int q12 = (set.getQ() - 1) / 2;
        ArrayList<BigInteger> h = Encoding.byte2seq(encoded, 6144, 5, 8);
        return new RQ(
                set, h.stream().limit(set.getP()).mapToLong(l -> l.longValue() - q12).toArray());
    }

    public static RQ decode(SntrupParameterSet set, byte[] encodedRq) {
        ArrayList<Integer> r = new ArrayList<>();
        for (byte b : encodedRq) {
            r.add((int) b & 0xff);
        }
        ArrayList<Integer> m =
                IntStream.range(0, set.getP())
                        .map(i -> set.getQ())
                        .boxed()
                        .collect(Collectors.toCollection(ArrayList::new));

        assertTrue(r.stream().filter(i -> i < 0).findFirst().isEmpty());
        assertFalse(
                IntStream.range(0, set.getP())
                        .filter(i -> r.get(i) > m.get(i))
                        .findFirst()
                        .isPresent());

        ArrayList<Integer> coef = Encoding.decode(r, m);
        return new RQ(set, coef.stream().mapToLong(l -> l - (set.getQ() - 1) / 2).toArray());
    }

    @Override
    public String toString() {
        return rQ.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        RQ rq = (RQ) obj;
        return set == rq.set && Objects.equals(rQ, rq.rQ);
    }

    @Override
    public int hashCode() {
        return Objects.hash(set, rQ);
    }
}
