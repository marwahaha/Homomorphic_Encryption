package java.security;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Random;

import java.security.PaillierPK;
import java.security.PaillierSK;
import java.security.DGKPrivateKey;
import java.security.DGKPublicKey;

/*
 * DGK Code was translated from C++ thanks to:
 * https://github.com/Bvinhmau/DGK-outsourced
 * Credits to Andrew Quijano for code conversion and 
 * Samet Tonyali for helping on revising the code/debugging it.
 * 
 * DGK was created in 2007 by:
 * Ivan Damgard, Martin Geisler, and Mikkel Kroigaard (DGK).
 * Title of Papers: 
 * Efficient and Secure Comparison for On-Line auctions (2007)
 * A correction to Efficient and Secure Comparison for Online auctions(2009)
 * Protocol 3 and Protocol 4 was created referencing Thjis Veugen's Paper:
 * Improving the DGK Comparison Protocol (2012)
 */

public class DGKOperations
{
	private static int l = 16, t = 160, k = 1024;
	private static DGKPublicKey pubKey;
	private static DGKPrivateKey privkey;
	private static Random rnd = new Random();
	private static int certainty = 40;
	// Probability of getting prime is 1-(1/2)^40

	public DGKOperations(int newl, int newt, int newk)
	{
		l = newl;
		t = newt;
		k = newk;
		GenerateKeys(l, t, k);
	}

	public static void GenerateKeys(int l, int t, int k)
	{
		System.out.println("Generating Keys...");

		// First check that all the parameters of the KeyPair are coherent throw an exception otherwise
		if (l < 0 || l > 32 )
		{
			throw new IllegalArgumentException("DGK Keygen Invalid parameters : plaintext space must be less than 32 bits");
		}

		if (l > t ||  t > k )
		{
			throw new IllegalArgumentException("DGK Keygen Invalid parameters: we must have l < k < t");
		}

		if ( k/2 < t + l + 1 )
		{
			throw new IllegalArgumentException("DGK Keygen Invalid parameters: we must have k > k/2 < t + l ");
		}

		if ( t%2 != 0 )
		{
			throw new IllegalArgumentException("DGK Keygen Invalid parameters: t must be divisible by 2 ");
		}

		BigInteger p, rp;
		BigInteger q, rq;
		BigInteger g, h ;
		BigInteger n, r ;
		long u = exponent(2,l);
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
			System.out.println("p is generated");

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

				System.out.println("q is not prime");
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

		// Preemptively build key with just the variables and 
		// not the Lookup Tables
		pubKey =  new DGKPublicKey(n, g, h, u, l, t, k);
		privkey = new DGKPrivateKey(p, q, vp, vq, u);

		System.out.println("Generating hashmaps...");
		privkey.generategLUT(pubKey);
		pubKey.generategLUT();
		pubKey.generatehLUT();
		System.out.println("FINISHED WITH DGK KEY GENERATION!");
	}//End of Generate Key Method

	/*
	 * Purpose: 
	 * Test method to confirm DGK's homormophic properties work
	 * as expected
	 */

	public static void testDGK(DGKPublicKey pubKey, DGKPrivateKey privKey)
	{
		long testDecrypt;
		BigInteger test;
		System.out.println("Testing DGK encryption/decryption...");
		System.out.println("Phase 1, Test encryption/decryption");
		for (int i=0;i<pubKey.u;i++)
		{
			test = DGKOperations.encrypt(pubKey, (long)i);
			testDecrypt = DGKOperations.decrypt(pubKey, privKey, test);
			if (i==testDecrypt)
			{
				//System.out.println("SUCESS AT ENCRYPT/DECRYPT: " + i);
				System.out.println(i);
			}
			else
			{
				System.out.println("FAILURE AT ENCRYPT/DECRYPT: " + i);
				System.exit(1);
			}
		}
		System.out.println("Test Additive homomorphism");

		System.out.println("Test Cipher Multiplcation with Scalar");

		System.out.println("Testing DGK encryption/decryption complete!!");
	}

	public DGKPublicKey getPublicKey()
	{
		return pubKey;
	}

	public DGKPrivateKey getPrivateKey()
	{
		return privkey;
	}

	public static BigInteger encrypt(DGKPublicKey pubKey, BigInteger plaintext)
	{
		return encrypt(pubKey, plaintext.mod(pubKey.bigU).longValue());
	}

	public static BigInteger encrypt(DGKPublicKey pubKey, long plaintext)
	{
		int t = pubKey.t;
		BigInteger n = pubKey.n;
		BigInteger h = pubKey.h;
		BigInteger u = pubKey.bigU;
		int U=u.intValue();
		//Through error is plain text not in Zu
		BigInteger ciphertext;

		if (plaintext < 0)
		{
			//throw new IllegalArgumentException("Encryption Invalid Parameter: the plaintext is not in Zu (plaintext < 0)"
			//	+ " value of Plain Text is: " + plaintext);
			System.err.println("ERROR SPOTTED: PLAINTEXT < 0 AT ENCRYPT");
			plaintext = NTL.POSMOD(plaintext,u).longValue();
		}
		if (plaintext >= U)
		{
			//throw new IllegalArgumentException("Encryption Invalid Parameter: the plaintext is not in Zu"
			//+ " (plaintext >= U) value of Plain Text is: " + plaintext);
			System.err.println("ERROR SPOTTED: PLAINTEXT > U AT ENCRYPT");
			plaintext=plaintext%U;
		}

		// If it is null, just fill the HashMap to avoid Null Pointer!
		if (pubKey.gLUT.get(plaintext)==null)
		{
			//System.out.println("New (ENCRYPTION TABLE) Value added for : " + plaintext);
			//Overwrite the HashMap
			pubKey.gLUT.put(plaintext, pubKey.g.modPow(BigInteger.valueOf(plaintext),n));
			//first part = g^m (mod n)
		}

		// Generate 2*t bit random number
		BigInteger r = NTL.generateXBitRandom(2*pubKey.t);
		r = r.setBit(2*t-1);

		//First part = g^m
		BigInteger firstpart = pubKey.gLUT.get(plaintext);
		BigInteger secondpart = BigInteger.ZERO;

		if (h.equals(BigInteger.ZERO))
		{
			secondpart = BigInteger.ZERO;
		}
		secondpart = BigInteger.ONE;

		BigInteger tempH;
		for(int i = 0; i < r.bitLength(); ++i)
		{
			//second part = h^r
			if(NTL.bit(r, i) == 1)
			{
				//System.out.println("Value of Second Part: (inside for):" + secondpart);
				tempH = pubKey.hLUT.get((long) i);
				if(tempH == null)
				{
					BigInteger e = new BigInteger("2").modPow(BigInteger.valueOf((long)(i)),n);
					//e = 2^i (mod n)
					BigInteger out = h.modPow(e,n);
					//h^{2^i (mod n)} (mod n)
					pubKey.hLUT.put((long)i, out);
					//f(i) = h^{2^i}(mod n)
					
					tempH = out;
				}
				secondpart = secondpart.multiply(tempH);
			}
		}
		//System.out.println("Value of Second Part: " + secondpart);
		ciphertext = NTL.POSMOD(firstpart.multiply(secondpart), n);
		return ciphertext;
	}

	public static long decrypt(DGKPublicKey pubKey, DGKPrivateKey privKey, BigInteger ciphertext)
	{
		BigInteger vp = privKey.getVP();
		BigInteger p = privKey.getP();
		BigInteger n = pubKey.n;

		if (ciphertext.signum()==-1)
		{
			//throw new IllegalArgumentException("decryption Invalid Parameter : the cipher text is not in Zn, "
			//+ "value of cipher text is: (c < 0)" + cipher text);
			System.err.println("ERROR SPOTTED: CIPHER TEXT IS NEGATIVE! (DECRYPT)");
			ciphertext = NTL.POSMOD(ciphertext, n);
		}
		if(ciphertext.compareTo(n)==1)
		{
			//throw new IllegalArgumentException("decryption Invalid Parameter : the cipher text is not in Zn,"
			//+ " value of cipher text is: (c > n)" + cipher text);
			System.err.println("ERROR SPOTTED: CIPHER TEXT > n (DECRYPT)");
			ciphertext = ciphertext.mod(n);
		}

		BigInteger decipher =  NTL.POSMOD(ciphertext,p).modPow(vp,p);
		/*
			c = g^m * h^r (mod n)
			c^vp (mod p) = g^{vp*m} (mod p)
			Because h^{vp} (mod p) = 1
		 */

		if (privKey.GetLUT().get(decipher)==null)
		{
			BigInteger tempP = privKey.getP();
			BigInteger gvp = NTL.POSMOD(pubKey.g,privKey.getP()).modPow(privKey.getVP(),privKey.getP());
			for (int i=0; i<pubKey.u; ++i)
			{
				BigInteger newDecipher = gvp.modPow(NTL.POSMOD(BigInteger.valueOf((long) i),tempP),tempP);
				//pwOne.println(decipher + "," + i);
				privKey.GetLUT().put(newDecipher,(long)i);

				//If I don't need to compute the whole table
				//Then don't do it!
				if(newDecipher.equals(decipher))
				{
					break;
				}
			}
		}
		long plain = -1;
		try
		{
			plain = privKey.GetLUT().get(decipher);
		}
		catch (NullPointerException nfe)
		{
			System.err.println("Issue: DGK Private Key mismatch!");
			nfe.printStackTrace();
		}
		return plain;
	}

	//Cipher a * Cipher b
	public static BigInteger DGKAdd(DGKPublicKey pubKey, BigInteger a, BigInteger b)
	{
		BigInteger n= pubKey.n;
		if (a.signum()==-1 ||b.signum()==-1)
		{
			//throw new IllegalArgumentException("DGKAdd Invalid Parameter : at least one of the ciphertext is not in Zn");
			a = a.mod(n);
			b = b.mod(n);
			System.err.println("ERROR SPOTTED: CipherText a OR CipherText b is NEGATIVE (DGKAdd)");
		}
		if (a.compareTo(n) == 1 || b.compareTo(n)==1)
		{
			System.err.println("ERROR SPOTTED: CipherText a OR CipherText b > n (DGKAdd)");
			a = NTL.POSMOD(a, n);
			b = NTL.POSMOD(b, n);
		}
		BigInteger result = a.multiply(b).mod(n);
		//Originally called MulMod...Method not found...
		//Assume a*b(mod n)
		return result;
	}

	public static BigInteger DGKSubtract(DGKPublicKey pubKey, BigInteger a, BigInteger b)
	{
		return DGKOperations.DGKAdd(pubKey, a, DGKOperations.DGKMultiply(pubKey, b, pubKey.u - 1));
		//This one works as well...but if you want to keep everything > 0, use above code!
		//return DGKOperations.DGKAdd(pubKey, a, DGKOperations.DGKMultiply(pubKey, b, - 1));
	}

	//cipher a * Plain text
	public static BigInteger DGKMultiply(DGKPublicKey pubKey, BigInteger cipher, long plaintext)
	{
		return DGKMultiply(pubKey, cipher, BigInteger.valueOf(plaintext));
	}

	public static BigInteger DGKMultiply(DGKPublicKey pubKey, BigInteger cipher, BigInteger plaintext)
	{
		BigInteger n = pubKey.n;
		BigInteger bigU = pubKey.bigU;
		if (cipher.signum()==-1)
		{
			//throw new IllegalArgumentException("DGKMultiply Invalid Parameter :  the ciphertext is not in Zn");
			System.err.println("ERROR SPOTTED: CIPHER TEXT IS NEGATIVE (DGKMULTIPLY)");
			cipher = NTL.POSMOD(cipher,n);
		}
		else if(cipher.compareTo(n)==1)
		{
			//throw new IllegalArgumentException("DGKMultiply Invalid Parameter :  the ciphertext is not in Zn");
			System.err.println("ERROR SPOTTED: CIPHER TEXT IS > N (DGKMULTIPLY)");
			cipher.mod(n);
		}
		if (plaintext.signum()==-1)
		{
			// COMMENTED OUT BECAUSE OF SST REU PROJECT
			//System.err.println("ERROR SPOTTED: PLAIN TEXT IS < 0 (DGKMULTIPLY)");
			plaintext = NTL.POSMOD(plaintext, n);
		}
		else if(plaintext.compareTo(bigU)==1)
		{
			System.err.println("ERROR SPOTTED: PLAIN TEXT IS > U (DGKMULTIPLY)");
			plaintext = plaintext.mod(bigU);
		}
		BigInteger result = cipher.modPow(plaintext,n);
		return result;
	}
	
	public static BigInteger DGKDivide(DGKPublicKey pubKey, BigInteger cipher, BigInteger plaintext)
	{
		BigInteger n = pubKey.n;
		BigInteger bigU = pubKey.bigU;
		if (cipher.signum()==-1)
		{
			//throw new IllegalArgumentException("DGKMultiply Invalid Parameter :  the ciphertext is not in Zn");
			System.err.println("ERROR SPOTTED: CIPHER TEXT IS NEGATIVE (DGKMULTIPLY)");
			cipher = NTL.POSMOD(cipher,n);
		}
		else if(cipher.compareTo(n)==1)
		{
			System.err.println("ERROR SPOTTED: CIPHER TEXT IS > N (DGKMULTIPLY)");
			cipher.mod(n);
		}
		if (plaintext.signum()==-1)
		{
			//if (!plaintext.equals(new BigInteger("-1")))
			//{
			System.err.println("ERROR SPOTTED: PLAIN TEXT IS < 0 (or < -1 depending on your setting) (DGKMULTIPLY)");
			plaintext = NTL.POSMOD(plaintext, n);
			//throw new IllegalArgumentException("DGKMultiply Invalid Parameter :  the plaintext is not in Zu");
			//}
		}
		else if(plaintext.compareTo(bigU)==1)
		{
			System.err.println("ERROR SPOTTED: PLAIN TEXT IS > U (DGKMULTIPLY)");
			plaintext = plaintext.mod(bigU);
		}
		//to set up [x]^(d^{-1})
		plaintext = plaintext.modInverse(n);
		BigInteger result = cipher.modPow(plaintext,n);
		return result;
	}
	
	public static BigInteger DGKDivide(DGKPublicKey pubKey, BigInteger cipher, long plaintext)
	{
		return DGKDivide(pubKey, cipher, BigInteger.valueOf(plaintext));
	}
	
	public static BigInteger DGKSum (DGKPublicKey pubKey, BigInteger [] parts)
	{
		BigInteger sum = DGKOperations.encrypt(pubKey, 0);
		for (int i = 0; i < parts.length; i++)
		{
			sum = DGKAdd(pubKey, sum, parts[i]);
		}
		return sum;
	}
	
	public static BigInteger DGKSum (DGKPublicKey pubKey, BigInteger [] parts, int limit)
	{
		BigInteger sum = parts[0];
		if (limit > parts.length)
		{
			return DGKSum(pubKey, parts);
		}
		
		for (int i = 1; i < parts.length; i++)
		{
			sum = DGKAdd(pubKey, sum, parts[i]);
		}
		return sum;
	}

	//===============================================COMPUTATIONAL METHODS USED=====================================

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

	public static BigInteger Protocol2
	(BigInteger x, BigInteger y,
			DGKPublicKey pubKey, DGKPrivateKey privKey,
			PaillierPK pk, PaillierSK sk)
	{
		// Note [[x]] and [[y]] is PAILLIER ENCRYPTED!
		// and [x] and [y] is DGK encrypted!

		int l = pubKey.l - 2;

		BigInteger powL = BigInteger.valueOf(exponent(2,l));//2^l
		System.out.println("2^l: "+ powL);

		// Alice, Step 1, 0 <= r < N
		BigInteger bigR = NTL.RandomBnd(pubKey.u);
		System.out.println("r: " + bigR);

		//Step 2, Alice computes [[x - y + 2^l + r]]
		BigInteger xminusy = Paillier.subtract(x, y, pk);//[[x - y]]
		System.out.println("x - y: " + Paillier.decrypt(xminusy, sk));

		BigInteger newData = Paillier.encrypt(bigR.add(powL), pk);//[[2^l + r]]
		System.out.println("z + 2^l: " + Paillier.decrypt(newData, sk));

		BigInteger z = Paillier.add(xminusy, newData, pk);//[[z]] = [[x - y + 2^l + r]]

		System.out.println("value of Z: " + Paillier.decrypt(z, sk));

		// Step 2, Bob
		BigInteger plainZ = Paillier.decrypt(z, sk);

		//beta = z (mod 2^l)
		BigInteger betaZZ = NTL.POSMOD(plainZ, powL);

		//Step 3: alpha = r (mod 2^l)
		BigInteger alphaZZ = NTL.POSMOD(bigR, powL);

		System.out.println("alpha: " + alphaZZ);
		System.out.println("beta: " + betaZZ);

		//Step 4: Call Protocol 1 or Protocol 3
		BigInteger alphaLEQbeta = DGKOperations.Protocol3(alphaZZ, betaZZ, pubKey,privKey);
		alphaLEQbeta = Paillier.encrypt(decrypt(pubKey, privKey, alphaLEQbeta), pk);

		//Step 5: B sends GammaB and z/2^l
		BigInteger zdiv2L = Paillier.encrypt(plainZ.divide(powL), pk);

		//Step 6: Already done from Protocol 3 as I return the XOR

		//Step 7

		//[[r/2^l]]
		System.out.println(bigR.divide(powL));
		BigInteger rdiv2L = Paillier.encrypt(bigR.divide(powL), pk);
		//[[z/2^l]] * [[r/2^l]]^{-1} = [[z/2^l - r/2^l]]
		BigInteger result = Paillier.subtract(zdiv2L, rdiv2L, pk);
		System.out.println("[[z/2^l - r/2^l]]: " + Paillier.decrypt(result, sk));

		result = Paillier.subtract(result, alphaLEQbeta, pk);
		// = [[z/2^l]] * ([[r/2^l]] [[alpha < Beta]])^-1 
		// = [[z/2^l - r/2^l - (alpha <= beta)]]
		return result;
	}

	public static BigInteger Protocol3 (BigInteger x, BigInteger y,
			DGKPublicKey pubKey, DGKPrivateKey privKey)
	{
		BigInteger EncONE = DGKOperations.encrypt(pubKey, 1);//Consider this static...

		int max = Math.max(x.bitLength(), y.bitLength());

		if (x.bitLength() > y.bitLength())
		{
			return encrypt(pubKey, 0);
		}
		else if(x.bitLength() < y.bitLength())
		{
			return encrypt(pubKey, 1);
		}

		System.out.println("X:");
		System.out.println(x.toString(2));
		for (int i=0; i < max; i++)
		{
			System.out.print(NTL.bit(x, i));
		}
		System.out.println("");

		System.out.println("Y:");
		System.out.println(y.toString(2));

		//Step 1: Send encrypted y-bits
		BigInteger [] EncY = new BigInteger[max];
		for (int i=0; i < max; i++)
		{
			EncY[i] = encrypt(pubKey, NTL.bit(y, i));
			//System.out.print(decrypt(pubKey, privKey,EncY[i]));
		}

		System.out.println("");
		System.out.println("Below: x XOR y");

		//Step 2: compute Encrypted X XOR Y
		BigInteger [] encXORY = new BigInteger[max];
		for (int i = 0; i < max; i++)
		{
			//Enc[x XOR y] = [y_i]
			if (NTL.bit(x, i) == 0)
			{
				encXORY[i] = EncY[i];
			}
			//Enc[x XOR y] = [1] - [y_i]
			else
			{
				encXORY[i] = DGKSubtract(pubKey, EncONE, EncY[i]);
			}
			System.out.print(decrypt(pubKey, privKey, encXORY[i]));
		}
		System.out.println("");

		// Step 3: Select gamma A and set up C_i
		int GammaA = rnd.nextInt(2);
		//Protocol 3 only works if GammaA = 1, in ALL cases.
		//Protocol 3 doesn't work if x = y and GammaA = 0
		GammaA = 1;
		System.out.println("Gamma A is: " + GammaA);

		//Collect index of all index where x_i = GammaA
		ArrayList <Integer> ListofGammaA = new ArrayList<Integer>();
		for (int i=0;i<max;i++)
		{
			if (NTL.bit(x, i) == GammaA)
			{
				ListofGammaA.add(i);
			}
		}

		BigInteger [] C_i = new BigInteger [max];
		BigInteger product = encrypt(pubKey, 0);

		System.out.println("new C_i");
		for (int i = 0; i < max; i++)
		{
			C_i [max-1-i] = product;
			product = DGKAdd(pubKey,product, encXORY[i]);
			System.out.print(decrypt(pubKey, privKey,C_i[max-1-i]));
		}

		//Step 4B, alter C_i using Gamma A

		// [1] - [y_i bit]
		System.out.println("");
		System.out.println("1 - y_i:");
		BigInteger [] minus = new BigInteger[max];

		for(int i = 0; i < max; i++)
		{
			BigInteger temp = DGKSubtract(pubKey, encrypt(pubKey,1), EncY[i]);
			minus [i] = temp;
			System.out.print(decrypt(pubKey, privKey, minus[i]));
		}

		for (int i = 0; i < max; i++)
		{
			if (GammaA==0)
			{
				// Step 4 = [1] - [y_i bit] + [c_i]
				C_i[i]= DGKAdd(pubKey,C_i[i], minus[max-1-i]);
			}
			else
			{
				// Step 4 = [y_i] + [c_i]
				C_i[i]= DGKAdd(pubKey, C_i[i], EncY[max-1-i]);
			}
		}
		System.out.println("");
		System.out.println("Updated C_i");
		for (int i = 0; i < max; i++)
		{
			System.out.print(decrypt(pubKey, privKey, C_i[max-1-i]));
		}
		System.out.println("");
		
		//Step 5
		for (int i = 0; i < max;i++)
		{
			// if i is NOT in L, just place a random NON-ZERO
			if(!ListofGammaA.contains(i))
			{
				System.out.println("NOT in L: " + i);
				C_i[max-1-i] = encrypt(pubKey, 7);
			}
		}
		System.out.println("Updated C_i with blinding...");
		for (int i=0;i<max;i++)
		{
			System.out.print(decrypt(pubKey, privKey, C_i[max-1-i]));
		}
		System.out.println("");

		//Step 6: Compute gamma A XOR gamma B.
		int GammaB = 0;

		for (int i = 0; i < max; i++)
		{
			if (DGKOperations.decrypt(pubKey, privKey, C_i[i]) == 0)
			{
				GammaB=1;
				break;
			}
		}
		System.out.println("Gamma A: " + GammaA + " " + " Gamma B: " + GammaB);

		//Test if [x <= y] = 1 or 0
		if (GammaA == GammaB)// 1 XOR 1 = 0 and 0 XOR 0 = 0, so X > Y
		{
			System.out.println("X > Y");
			System.out.println(GammaA + " XOR " + GammaB);
			if(x.compareTo(y) == 1)
			{
				System.out.println("CORRECT!");
			}
			else
			{
				System.out.println("WRONG!");
			}
			return encrypt(pubKey, 0);
		}
		else // 1 XOR 0 = 1 and 0 XOR 1 = 1, so X <= Y 
		{
			System.out.println("X <= Y");
			System.out.println(GammaA + " XOR " + GammaB);
			if (x.compareTo(y) <= 0)
			{
				System.out.println("CORRECT!");
			}
			else
			{
				System.out.println("WRONG!");
			}
			return encrypt(pubKey, 1);
		}
	}
	
	public static BigInteger Protocol4
	(BigInteger x, BigInteger y,
			DGKPublicKey pubKey, DGKPrivateKey privKey,
			PaillierPK pk, PaillierSK sk)
	{
		// Note [[x]] and [[y]] is PAILLIER ENCRYPTED!
		// and [x] and [y] is DGK encrypted!

		BigInteger N = pk.n;
		long u = pubKey.u;
		int l = pubKey.l - 2;

		BigInteger powL = BigInteger.valueOf(exponent(2,l));//2^l

		// Alice, Step 1, 0 <= r < N
		BigInteger bigR = NTL.RandomBnd(N);

		System.out.println("big r: " + bigR);
		System.out.println("Bit size of r: " + bigR.bitLength());

		//Step 2, Alice computes [[x - y + 2^l + r]]
		BigInteger xminusy = Paillier.subtract(x, y, pk);//[[x - y]]
		BigInteger newData = Paillier.encrypt(bigR.add(powL), pk);//[[2^l + r]]
		BigInteger z = Paillier.add(xminusy, newData, pk);//[[z]] = [[x - y + 2^l + r]]

		// Step 2, Bob
		BigInteger plainZ = Paillier.decrypt(z, sk);

		//beta = z (mod 2^l)
		BigInteger betaZZ = NTL.POSMOD(plainZ, powL);

		//Step 3: alpha = r (mod 2^l)
		BigInteger alphaZZ = NTL.POSMOD(bigR, powL);

		System.out.println("alpha: " + alphaZZ);
		System.out.println("beta: " + betaZZ);

		/*
		 * Step 4 Begins: 
		 * DGK modified comparison algorithm
		 * input: alpha, beta
		 * output: gamma A and gamma B
		 */

		int GammaA = rnd.nextInt(2);//Get 0 or 1...
		BigInteger GammaB = null;
	
		/*
		 * if alphaZZ > betaZZ
		 * Then [alpha <= beta] = [0]
		 * This implies that GammaA == GammaB
		 * 1 XOR 1 = 0
		 * 0 XOR 0 = 0
		 */
		if(alphaZZ.bitLength() > betaZZ.bitLength())
		{
			GammaB = encrypt(pubKey, GammaA);
		}
		/*
		 * if alphaZZ < betaZZ
		 * Then [alpha < beta] = [1]
		 * 1 XOR 0 = 1
		 * 0 XOR 1 = 1
		 */
		else if (alphaZZ.bitLength() < betaZZ.bitLength())
		{
			if(GammaA == 1)
			{
				encrypt(pubKey, 0);
			}
			else
			{
				encrypt(pubKey, 1);
			}
		}
		/*
		 * Complete Protocol 4 regularly
		 * Both are confirmed same bit length
		 */
		else
		{
			/*
			 * Step 4A	
			 * Bob computes [d]
			 * and sends it to Alice
			 */
			BigInteger d;
			//if (N - 1)/2 < z, set bit to 1 for overflow
			BigInteger compare = N.subtract(BigInteger.ONE).divide(new BigInteger("2"));
			if (plainZ.compareTo(compare) == 1)
			{
				d = encrypt(pubKey,1);
			}
			else
			{
				d = encrypt(pubKey,0);
			}

			/*
			 * Step 4B:
			 * Bob sends encrypted bits of Beta to Alice
			 */
			long betaTab [] = new long [l];// Plain text Beta
			BigInteger encBetaTab [] = new BigInteger[l];//Encrypted Beta

			System.out.println("Binary value of alpha: ");
			for (int i = 0; i < l; i++)
			{
				System.out.print(NTL.bit(alphaZZ, i));
			}
			System.out.println("");

			System.out.println("Binary value of beta: ");
			for (int i = 0; i < l; i++)
			{
				betaTab[i] = NTL.bit(betaZZ, i);
				System.out.print(NTL.bit(betaZZ, i));
				encBetaTab[i] = encrypt(pubKey, betaTab[i]);
			}
			System.out.println("");

			/*
			 *  Step 4C:
			 *  Alice checks if
			 *  if r < (N - 1)/2
			 */
			
			compare = N.subtract(BigInteger.ONE).divide(new BigInteger("2"));
			if (bigR.compareTo(compare) == -1)// r < (N - 1)/2
			{
				d = encrypt(pubKey,0);
			}

			/*
			 * Step 4D:
			 * Compute Alpha XOR Beta
			 */
			BigInteger encAlphaXORBetaTab [] = new BigInteger[l];
			BigInteger W [] = new BigInteger[l];
			BigInteger c [] = new BigInteger[l+1];

			for (int i = 0; i < l; i++)
			{
				// alpha_i = 0 implies alpha_i XOR beta_i = beta_i
				if (NTL.bit(alphaZZ, i) == 0)
				{
					encAlphaXORBetaTab[i] = encBetaTab[i];
				}
				// alpha_i = 1 implies alpha_i XOR beta_i = 1 - beta_i
				else
				{
					encAlphaXORBetaTab[i] = DGKSubtract(pubKey, DGKOperations.encrypt(pubKey, 1), encBetaTab[i]);
				}
			}

			//Step 4E, Compute Alpha Hat and w_i
			BigInteger alphaHatZZ = NTL.POSMOD(bigR.subtract(N), powL);

			for (int i = 0; i < l; i++)
			{
				if (NTL.bit(alphaZZ, i) == NTL.bit(alphaHatZZ, i))
				{
					W[i] = encAlphaXORBetaTab[i];
				}
				else
				{
					W[i] = DGKSubtract(pubKey, encAlphaXORBetaTab[i], d);
				}
			}

			//Step 4F, Modify w_i
			BigInteger xorBitsSum = encrypt(pubKey,0);
			for (int i = 0; i < l; i++)
			{
				W[i] = DGKMultiply(pubKey, W[i], exponent(2, i));//xorBitsSum = [ 2^l*w[i] ]
				xorBitsSum = DGKAdd(pubKey, xorBitsSum, DGKMultiply(pubKey, W[i], 2));
			}

			//Step 4G
			//GammaA = rnd.nextInt(2);//Get 0 or 1...
			long s = 1 - 2*GammaA;

			//Step 4H
			BigInteger wProduct = encrypt(pubKey,0);
			for(int i = 0 ; i < l ; i++)
			{
				//Plain Text exponent
				long alphaexp = NTL.POSMOD( NTL.bit(alphaHatZZ,l-1-i) -  NTL.bit(alphaZZ,l-1-i), u);

				//[d]^(alpha hat bit - alpha bit)
				BigInteger dexponent = DGKMultiply(pubKey,d,alphaexp);

				//[s + alpha_i] = [s] * [alpha_i]
				BigInteger splusAlphaBit = encrypt(pubKey, NTL.POSMOD(s + NTL.bit(alphaZZ, l-1-i),N));

				//[s] * [alpha_i] * [d]^(alpha hat bit - alpha bit)
				BigInteger sum = DGKAdd(pubKey, splusAlphaBit, dexponent);

				//[s] * [alpha_i] * [d]^(alpha hat bit - alpha bit) * (beta_i)^{-1}
				sum = DGKSubtract(pubKey, sum, encBetaTab[l - 1 - i]);//
				c[l-1-i] = DGKAdd(pubKey, wProduct, sum);

				wProduct = DGKAdd(pubKey,wProduct,DGKMultiply(pubKey, W[l-1-i],3));
			}
			c[l] = DGKAdd(pubKey, encrypt(pubKey, GammaA), xorBitsSum);

			//Step 4I
			for (int i=0;i < c.length; i++)
			{
				// Step 4i: Get Random Number size 2t bits
				// BigInteger rBlind = NTL.RandomBits_ZZ(pubKey.t);
				//SetBit(rBlind, pubKey.t * 2 - 1);//Step 4i: I am not sure why do this??
				//c[i] = DGKMultiply(pubKey,c[i], rBlind);
			}

			// Step 4J: Compute GammaB
			GammaB =  encrypt(pubKey,0);//GAMMA B IS HERE
			for(int i = 0 ; i < l+1 ; i++)
			{
				if(decrypt(pubKey, privKey,c[i]) == 0)//**********************PRIVATE KEY************************8
				{
					GammaB = encrypt(pubKey,1);//GAMMA B IS HERE
					break;
				}
			}

		}
				
		//Step 5: B sends GammaB and z/2^l
		BigInteger zdiv2L = Paillier.encrypt(plainZ.divide(powL), pk);

		// Step 6: Compute GammaA XOR GammaB
		BigInteger betaInfAlpha;
		if (GammaA == 1)
		{
			betaInfAlpha = GammaB;
		}
		else
		{
			betaInfAlpha = Paillier.encrypt(Paillier.subtract(Paillier.encrypt(BigInteger.ONE, pk), GammaB, pk), pk);
		}

		if (decrypt(pubKey,privKey,GammaB)==GammaA)
		{
			System.out.println("alpha <= Beta");
			if (alphaZZ.compareTo(betaZZ)==0
					|| alphaZZ.compareTo(betaZZ)==-1)
			{
				System.out.println("CORRECT");
			}
			else
			{
				System.out.println("WRONG");
			}
		}
		else
		{
			System.out.println("alpha > Beta");
			if (alphaZZ.compareTo(betaZZ)==1)
			{
				System.out.println("CORRECT");
			}
			else
			{
				System.out.println("WRONG");
			}
		}

		//Step 7

		//[[r/2^l]]
		BigInteger rdiv2L = Paillier.encrypt(bigR.divide(powL), pk);
		//[[z/2^l]] * [[r/2^l]]^{-1} = [[z/2^l - r/2^l]]
		BigInteger result = Paillier.subtract(zdiv2L, rdiv2L, pk); 
		result = Paillier.subtract(result, betaInfAlpha, pk);
		//[[z/2^l]] * ([[r/2^l]] [[alpha < Beta]])^-1 - [[z/2^l - r/2^l - (alpha < beta)]]
		return result;
	}
	
}//END OF CLASS