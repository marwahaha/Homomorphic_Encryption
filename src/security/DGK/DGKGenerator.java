package security.DGK;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;

public class DGKGenerator extends KeyPairGeneratorSpi
{
	private int l = 16, t = 160, k = 1024;
	private SecureRandom rnd = null;
	private final static int certainty = 40;
	private boolean no_skip_public_key_maps = true;
	
	public DGKGenerator(int _l, int _t, int _k)
	{
		// First check that all the parameters of the KeyPair are coherent throw an exception otherwise
		if (_l < 0 || _l > 32 )
		{
			throw new IllegalArgumentException("DGK Keygen Invalid parameters : plaintext space must be less than 32 bits");
		}

		if (_l > _t || _t > _k )
		{
			throw new IllegalArgumentException("DGK Keygen Invalid parameters: we must have l < k < t");
		}

		if (_k/2 < _t + _l + 1 )
		{
			throw new IllegalArgumentException("DGK Keygen Invalid parameters: we must have k > k/2 < t + l ");
		}

		if (_t%2 != 0 )
		{
			throw new IllegalArgumentException("DGK Keygen Invalid parameters: t must be divisible by 2 ");
		}
		
		l = _l;
		t = _t;
		k = _k;
		this.initialize(k, null);
	}
	
	public void initialize(int keysize, SecureRandom random) 
	{
		if (keysize == 0)
		{
			no_skip_public_key_maps = false;
		}
		
		if (random == null)
		{
			rnd = new SecureRandom();
		}
		else
		{
			rnd = random;
		}
	}

	public KeyPair generateKeyPair() 
	{
		DGKPublicKey pubKey = null;
		DGKPrivateKey privkey = null;
		
		System.out.println("Generating Keys...");

		BigInteger p, rp;
		BigInteger q, rq;
		BigInteger g, h ;
		BigInteger n, r ;
		long u = exponent(2, l);
		BigInteger vp, vq, vpvq, tmp;

		while(true)
		{
			//Following the instruction as stated on DGK C++ counterpart
			u = NTL.NextPrime(u + exponent(2, 10));
			vp = new BigInteger(t, certainty, rnd);//(160, 40, random)
			vq = new BigInteger(t, certainty, rnd);//(160, 40, random)
			vpvq = vp.multiply(vq);
			tmp = BigInteger.valueOf(u).multiply(vp);// u * vp

			System.out.println("Completed generating vp, vq");

			int needed_bits = k/2 - (tmp.bitLength());

			// Generate rp until p is prime such that u * vp divides p-1
			do
			{
				rp = new BigInteger(needed_bits, rnd);
				rp = rp.setBit(needed_bits - 1);
				/*
				 * from NTL:
				 * long SetBit(ZZ& x, long p);
				 * returns original value of p-th bit of |a|, and replaces p-th bit of
				 * a by 1 if it was zero; low order bit is bit 0; error if p < 0;the sign of x is maintained
				 */

				/*
				 * p = rp * u * vp + 1
				 * u | p - 1
				 * vp | p - 1
				 */
				p = rp.multiply(tmp).add(BigInteger.ONE);
			}
			while(!p.isProbablePrime(certainty));

			//Thus we ensure that p is a prime, with p-1 divisible by prime numbers vp and u
			//I can implement AKS for 100% certainty if need be

			tmp = BigInteger.valueOf(u).multiply(vq);
			needed_bits = k/2 - (tmp.bitLength());
			do
			{
				// Same method for q than for p
				rq = new BigInteger(needed_bits, rnd);//(512,40,random)
				rq = rq.setBit(needed_bits -1);
				q = rq.multiply(tmp).add(BigInteger.ONE); // q = rq*(vq*u) + 1
				//

				/*
				 * q - 1 | rq * vq * u
				 * Therefore,
				 * c^{vp} = g^{vp*m} (mod n) because
				 * rq | (q - 1)
				 */
			}
			while(!q.isProbablePrime(certainty));
			//Thus we ensure that q is a prime, with p-1 divides the prime numbers vq and u

			if(!NTL.POSMOD(rq,BigInteger.valueOf(u)).equals(BigInteger.ZERO) && !NTL.POSMOD(rp,BigInteger.valueOf(u)).equals(BigInteger.ZERO))
			{
				break;
			}
			
		} //end while loop 1: Generated p and q
		
		n = p.multiply(q);
		tmp = rp.multiply(rq).multiply(BigInteger.valueOf(u));
		System.out.println("While Loop 1 completed: n, p and q generated.");

		while(true)
		{
			//Generate n bit random number
			r = NTL.generateXBitRandom(n.bitLength());	

			h = r.modPow(tmp,n); // h = r^{rp*rq*u} (mod n)

			if (h.equals(BigInteger.ONE))
			{
				continue;
			}

			if (h.modPow(vp,n).equals(BigInteger.ONE))
			{
				continue;//h^{vp}(mod n) = 1
			}

			if (h.modPow(vq,n).equals(BigInteger.ONE))
			{
				continue;//h^{vq}(mod n) = 1
			}

			if (h.modPow(BigInteger.valueOf(u), n).equals(BigInteger.ONE))
			{
				continue;//h^{u}(mod n) = 1
			}

			if (h.modPow(BigInteger.valueOf(u).multiply(vq), n).equals(BigInteger.ONE))
			{
				continue;//h^{u*vq} (mod n) = 1
			}

			if (h.modPow(BigInteger.valueOf(u).multiply(vp), n).equals(BigInteger.ONE))
			{
				continue;//h^{u*vp} (mod n) = 1
			}

			if (h.gcd(n).equals(BigInteger.ONE))
			{
				break;//(h, n) = 1
			}
		}

		BigInteger rprq = rp.multiply(rq);
		System.out.println("While loop 2: h is generated");

		while(true)
		{
			r = NTL.generateXBitRandom(n.bitLength());

			g = r.modPow(rprq,n); //g = r^{rp*rq}(mod n)

			if (g.equals(BigInteger.ONE))
			{
				continue;// g = 1
			}

			if (!g.gcd(n).equals(BigInteger.ONE))
			{
				continue;//(g, n) must be relatively prime
			}
			// h can still be of order u, vp, vq , or a combination of them different that u, vp, vq

			if (g.modPow(BigInteger.valueOf(u),n).equals(BigInteger.ONE))
			{
				continue;//g^{u} (mod n) = 1
			}

			if (g.modPow(BigInteger.valueOf(u).multiply(BigInteger.valueOf(u)),n).equals(BigInteger.ONE))
			{
				continue;//g^{u*u} (mod n) = 1
			}

			if (g.modPow(BigInteger.valueOf(u).multiply(BigInteger.valueOf(u)).multiply(vp),n).equals(BigInteger.ONE))
			{
				continue;//g^{u*u*vp} (mod n) = 1
			}

			if (g.modPow(BigInteger.valueOf(u).multiply(BigInteger.valueOf(u)).multiply(vq),n).equals(BigInteger.ONE))
			{
				continue;//g^{u*u*vp} (mod n) = 1
			}

			if (g.modPow(vp,n).equals(BigInteger.ONE))
			{
				continue;//g^{vp} (mod n) = 1
			}

			if (g.modPow(vq,n).equals(BigInteger.ONE))
			{
				continue;//g^{vq} (mod n) = 1
			}

			if (g.modPow(BigInteger.valueOf(u).multiply(vq),n).equals(BigInteger.ONE))
			{
				continue;//g^{u*vq}(mod n) = 1
			}

			if (g.modPow(BigInteger.valueOf(u).multiply(vp),n).equals(BigInteger.ONE))
			{
				continue;//g^{u*vp} (mod n) = 1
			}

			if (g.modPow(vpvq,n).equals(BigInteger.ONE))
			{
				continue;//g^{vp*vq} (mod n) == 1
			}

			if (NTL.POSMOD(g,p).modPow(vp,p).equals(BigInteger.ONE))
			{
				continue; //g^{vp} (mod p) == 1
			}

			if ((NTL.POSMOD(g,p).modPow(BigInteger.valueOf(u),p).equals(BigInteger.ONE)))
			{
				continue;//g^{u} (mod p) = 1
			}

			if (NTL.POSMOD(g,q).modPow(vq,q).equals(BigInteger.ONE))
			{
				continue;//g^{vq}(mod q) == 1
			}

			if ((NTL.POSMOD(g,q).modPow(BigInteger.valueOf(u),q).equals(BigInteger.ONE)))
			{
				continue;//g^{u}(mod q)
			}
			break;
		}
		System.out.println("While loop 3: g is generated");

		// Preemptively build key with just the variables and 
		// not the Lookup Tables
		pubKey =  new DGKPublicKey(n, g, h, u, l, t, k);
		privkey = new DGKPrivateKey(p, q, vp, vq, u);

		System.out.println("Generating hashmaps...");
		privkey.generategLUT(pubKey);
		if(no_skip_public_key_maps)
		{
			pubKey.generategLUT();
			pubKey.generatehLUT();
		}
		System.out.println("FINISHED WITH DGK KEY GENERATION!");
		return new KeyPair(pubKey, privkey);
	}
	
	private static int exponent(int base, int exponent)
	{
		int answer = 1;
		int counter = exponent;
		while (counter != 0)
		{
			answer*=base;
			--counter;
		}
		return answer;
	}
}
