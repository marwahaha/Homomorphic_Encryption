package java.security;

/*

This is the Java implementation of the C++ NTL Library
Please refer to this site for NTL documentation:
http://www.shoup.net/ntl/doc/tour.html
http://www.shoup.net/ntl/doc/ZZ.txt

Credits to Andrew Quijano for code conversion 
and Samet Tonyali for helping on revising the code/debugging it.

Feel free to use this code as you like.
*/

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Random;

public class NTL
{
    private static Random rnd = new Random();
    
    public static boolean AKSTest(BigInteger p)
    {
        //(x-1)^p - (x^p - 1)
        //Test if p divides all the coefficients
        //excluding the first and last term of (x-1)^p
        //If it can divide all of them then p is a prime

        //Using Binomial Theorem, I obtain the coefficients of all
        //terms from the expansion (x-1)^p
        ArrayList<BigInteger> coeff = BinomialTheorem(p);

        coeff.remove(0); //Remove first term
        coeff.remove(coeff.remove(coeff.size()-1)); //Remove last term

        for (int i=0;i<coeff.size();i++)
        {
            //System.out.println(coeff.get(i));
            //System.out.println(coeff.get(i).mod(p));
            if (!coeff.get(i).mod(p).equals(BigInteger.ZERO))
            {
                return false;
            }
        }
        return true;
    }
    
    //AKS-Test, I can use binomial theorem
    public static ArrayList<BigInteger> BinomialTheorem (BigInteger x)
    {
        ArrayList<BigInteger> coeff = new ArrayList<BigInteger>();
		/*
		 * 	Binomial Theorem: Choose
		 * 	n	n	n	...	n
		 * 	0	1	2	...	n
		 */
        BigInteger start = BigInteger.ZERO;
        while (! (start.equals(x.add(BigInteger.ONE))) )
        {
            coeff.add(nCr(x,start));
            start = start.add(BigInteger.ONE);
        }
        return coeff;
    }

    public static BigInteger nCr (BigInteger n, BigInteger r)
    {
        BigInteger nCr=factorial(n);
        nCr=nCr.divide(factorial(r));
        nCr=nCr.divide(factorial(n.subtract(r)));
        //nCr = n!/r!(n-r)!
        //or (n * n-1 * ... r+1)/(n-r)!
        return nCr;
    }

    public static BigInteger factorial(BigInteger x)
    {
        BigInteger result = BigInteger.ONE;
        BigInteger n = x;
        while (!n.equals(BigInteger.ZERO))
        {
            result = result.multiply(n);
            n= n.subtract(BigInteger.ONE);
        }
        return result;
    }

    public static BigInteger bigIntSqRootFloor(BigInteger x)
            throws IllegalArgumentException
    {
        if (x.compareTo(BigInteger.ZERO) < 0)
        {
            throw new IllegalArgumentException("Negative argument.");
        }
        // square roots of 0 and 1 are trivial and
        // y == 0 will cause a divide-by-zero exception
        if (x .equals(BigInteger.ZERO) || x.equals(BigInteger.ONE))
        {
            return x;
        } // end if
        BigInteger two = BigInteger.valueOf(2L);
        BigInteger y;
        // starting with y = x / 2 avoids magnitude issues with x squared
        for (y = x.divide(two);
             y.compareTo(x.divide(y)) > 0;
             y = ((x.divide(y)).add(y)).divide(two));
        return y;
    }

    public static BigInteger bigIntSqRootCeil(BigInteger x)
            throws IllegalArgumentException
    {
        if (x.compareTo(BigInteger.ZERO) < 0)
        {
            throw new IllegalArgumentException("Negative argument.");
        }
        // square roots of 0 and 1 are trivial and
        // y == 0 will cause a divide-by-zero exception
        if (x == BigInteger.ZERO || x == BigInteger.ONE)
        {
            return x;
        } // end if
        BigInteger two = BigInteger.valueOf(2L);
        BigInteger y;
        // starting with y = x / 2 avoids magnitude issues with x squared
        for (y = x.divide(two);
             y.compareTo(x.divide(y)) > 0;
             y = ((x.divide(y)).add(y)).divide(two));
        if (x.compareTo(y.multiply(y)) == 0)
        {
            return y;
        }
        else
        {
            return y.add(BigInteger.ONE);
        }
    }

    public static BigInteger NextPrime (BigInteger x)
    {
        //Find next Prime number after x
        //Example if x =18, return 19 (closest prime)

        if(x.mod(new BigInteger("2")).equals(BigInteger.ZERO))
        {
            x=x.add(BigInteger.ONE);
        }

        while (true)
        {
            if (isPrime(x))
            {
                return x;
            }
            //System.out.print(x.toString());
            x = x.add(new BigInteger("2"));
        }
    }
    
    public static long NextPrime(long x)
    {
    	BigInteger temp = NTL.NextPrime(BigInteger.valueOf(x));
    	return temp.longValue();
    }

    public static boolean isPrime(BigInteger x)
    {
        BigInteger factor = new BigInteger("3");

        while (!factor.equals(x))
        {
            if (x.mod(factor).equals(BigInteger.ZERO))
            {
                return false;
            }
            factor=factor.add(new BigInteger("2"));
        }
        return true;
    }

    public static BigInteger POSMOD(BigInteger x, BigInteger n)
    {
        BigInteger answer = x.mod(n);
        answer = answer.add(n);
        answer = answer.mod(n);
        return answer;
    }

    public static long POSMOD(long x, long n)
    {
        return ((x%n)+n)%n;
    }

    public static BigInteger POSMOD(long x, BigInteger n)
    {
        return POSMOD(BigInteger.valueOf(x), n);
    }

    public static BigInteger generateXBitRandom (int n)
    {
        BigInteger r;
        do
        {
            r = new BigInteger(n, rnd);
        }
        while (!(r.bitLength()== n));//Ensure it is n-bit Large number
        return r;
    }

/*
void RandomBnd(ZZ& x, const ZZ& n);
ZZ RandomBnd(const ZZ& n);
void RandomBnd(long& x, long n);
long RandomBnd(long n);
x = pseudo-random number in the range 0..n-1, or 0 if n <= 0
*/

    public static BigInteger RandomBnd(long n)
    {
        return RandomBnd(BigInteger.valueOf(n));
    }

    public static BigInteger RandomBnd(BigInteger n)
    {
        if (n.signum() <= 0)
        {
            return BigInteger.ZERO;
        }
        BigInteger r;
        do
        {
            r = new BigInteger(n.bitLength(), rnd);
        }
        while (r.signum()== -1 || r.compareTo(n)>= 0);
        // 0 <= r <= n - 1
        // if r is negative or r >= n, keep generating random numbers
        return r;
    }
    
/*
void RandomBits(ZZ& x, long l);
ZZ RandomBits_ZZ(long l);
void RandomBits(long& x, long l);
long RandomBits_long(long l);
x = pseudo-random number in the range 0..2^L-1.
EXCEPTIONS: strong ES
*/

    public static BigInteger RandomBits_ZZ(int x)
    {
        BigInteger max = new BigInteger("2").pow(x);
        BigInteger r;
        do
        {
            r = new BigInteger(x, rnd);
        }
        //New number must be 0 <=  r <= 2^l - 1
        //If r >= 2^l or r <= 0 keep generating
        while (r.compareTo(max) >= 0 || r.signum()==-1);
        return r;
    }

    /*
    long bit(const ZZ& a, long k);
    long bit(long a, long k);
    returns bit k of |a|, position 0 being the low-order bit.
    If  k < 0 or k >= NumBits(a), returns 0.
    */
    
    public static int bit(BigInteger a, long k)
    {
    	//If the value k (location of bit is bigger than a
    	if (k >= a.bitLength())
    	{
    		return 0;
    	}
        if (k < 0)
        {
            return 0;
        }
        String bit = a.toString(2);//get it in Binary
        if (bit.charAt((int)k)== '0')
        {
        	return 0;
        }
        else
        {
        	return 1;
        }
    }

    public static int bit(long a, long k)
    {
    	return bit(BigInteger.valueOf(a), k);
    }
}