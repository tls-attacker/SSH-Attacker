/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core;

import static org.junit.Assert.assertEquals;

import cc.redberry.rings.IntegersZp64;
import cc.redberry.rings.poly.PolynomialMethods;
import cc.redberry.rings.poly.univar.UnivariateDivision;
import cc.redberry.rings.poly.univar.UnivariatePolynomialZp64;
import de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.util.Encoding;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.LongStream;

public class RQ {
    private SntrupParameterSet set;
    private UnivariatePolynomialZp64 rQ;
    private UnivariatePolynomialZp64 mod;

    public RQ(SntrupParameterSet set, long[] coefficient) {
        this.set = set;
        this.mod = genereateMod(set);
        setRQ(coefficient);
    }

    private RQ(SntrupParameterSet set, UnivariatePolynomialZp64 rq) {
        this.set = set;
        this.mod = genereateMod(set);
        this.rQ = rq;
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
        assertEquals(
                "Coefficients have to be between (-(q+1)/2 and (q+1)/2",
                Arrays.stream(coefficient)
                        .filter(c -> c > (set.getQ() + 1) / 2 || c < -(set.getQ() + 1) / 2)
                        .peek(c -> System.out.println(c))
                        .findFirst()
                        .isEmpty(),
                true);

        this.rQ =
                UnivariateDivision.remainder(
                        UnivariatePolynomialZp64.create(set.getQ(), coefficient), mod, true);
        assertEquals(true, rQ.isOverFiniteField());
    }

    public SntrupParameterSet getSet() {
        return set;
    }

    public LongStream stream() {
        return rQ.stream().map(c -> (c >= (set.getQ() + 1) / 2 ? c - set.getQ() : c));
    }

    public static RQ invert(RQ rq) {
        UnivariatePolynomialZp64[] xgcd =
                PolynomialMethods.PolynomialExtendedGCD(
                        UnivariatePolynomialZp64.create(rq.getSet().getQ(), rq.stream().toArray()),
                        genereateMod(rq.set));
        return new RQ(rq.getSet(), xgcd[1]);
    }

    public static RQ multiply(int val, Short shrt) {
        RQ convertedShrt = new RQ(shrt.getSet(), shrt.stream().toArray());
        return multiply(val, convertedShrt);
    }

    public static RQ multiply(int val, RQ rq) {
        return new RQ(
                rq.getSet(),
                UnivariateDivision.remainder(rq.getRQ().multiply(val), rq.getMod(), true));
    }

    public static RQ multiply(R r, RQ rq) {
        assert (r.getSet() == rq.getSet());
        RQ convertedR = new RQ(r.getSet(), r.stream().toArray());
        return multiply(convertedR, rq);
    }

    public static RQ multiply(RQ rq1, RQ rq2) {
        return new RQ(
                rq1.getSet(),
                UnivariateDivision.remainder(
                        rq1.getRQ().multiply(rq2.getRQ()), rq1.getMod(), true));
    }

    public static RQ multiply(Short shrt, RQ rq) {
        RQ convertedShrt = new RQ(rq.getSet(), shrt.stream().toArray());
        return multiply(convertedShrt, rq);
    }

    public static RQ multiply(Rounded rounded, RQ rq) {
        RQ convertedRounded = new RQ(rounded.getSet(), rounded.stream().toArray());
        return multiply(convertedRounded, rq);
    }

    public static RQ sub(Rounded rounded, RQ rq) {
        RQ convertedRounded = new RQ(rounded.getSet(), rounded.stream().toArray());
        return sub(convertedRounded, rq);
    }

    public static RQ sub(RQ rq1, RQ rq2) {
        return new RQ(
                rq1.getSet(),
                UnivariateDivision.remainder(
                        rq1.getRQ().subtract(rq2.getRQ()), rq1.getMod(), true));
    }

    public static RQ add(R r, RQ rq) {
        RQ convertedR = new RQ(r.getSet(), r.stream().toArray());
        return add(convertedR, rq);
    }

    public static RQ add(RQ rq1, RQ rq2) {
        return new RQ(
                rq1.getSet(),
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

        assertEquals(r.stream().filter(i -> i < 0).findFirst().isEmpty(), true);
        assertEquals(
                IntStream.range(0, set.getP())
                        .filter(i -> r.get(i) > m.get(i))
                        .findFirst()
                        .isPresent(),
                false);

        ArrayList<Integer> encdodedCoefficients = Encoding.encode(r, m);

        byte[] res = new byte[encdodedCoefficients.size()];
        for (int i = 0; i < encdodedCoefficients.size(); i++) {
            res[i] = (byte) (encdodedCoefficients.get(i).intValue());
        }
        return res;
    }

    public byte[] encode_old() {
        int q12 = (set.getQ() - 1) / 2;
        ArrayList<Integer> h =
                this.stream()
                        .mapToInt(l -> Math.toIntExact(l + q12))
                        .boxed()
                        .collect(Collectors.toCollection(ArrayList::new));
        for (int i = 0; i < ((-set.getP() + set.getP() * 5) % 5); i++) {
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
        for (int i = 0; i < encodedRq.length; i++) {
            r.add((int) encodedRq[i] & 0xff);
        }
        ArrayList<Integer> m =
                IntStream.range(0, set.getP())
                        .map(i -> set.getQ())
                        .boxed()
                        .collect(Collectors.toCollection(ArrayList::new));

        assertEquals(r.stream().filter(i -> i < 0).findFirst().isEmpty(), true);
        assertEquals(
                IntStream.range(0, set.getP())
                        .filter(i -> r.get(i) > m.get(i))
                        .findFirst()
                        .isPresent(),
                false);

        ArrayList<Integer> coef = Encoding.decode(r, m);
        return new RQ(set, coef.stream().mapToLong(l -> l - (set.getQ() - 1) / 2).toArray());
    }

    @Override
    public String toString() {
        return rQ.toString();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((rQ == null) ? 0 : rQ.hashCode());
        result = prime * result + ((set == null) ? 0 : set.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null) return false;
        if (getClass() != obj.getClass()) return false;
        RQ other = (RQ) obj;
        if (rQ == null) {
            if (other.rQ != null) return false;
        } else if (!rQ.equals(other.rQ)) return false;
        if (set != other.set) return false;
        return true;
    }
}
