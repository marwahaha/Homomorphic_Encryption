package security.DGK;

import java.math.BigInteger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import security.DGK.DGKPrivateKey;
import security.DGK.DGKPublicKey;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

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

public class DGKOperations extends CipherSpi
{
	protected byte[] engineDoFinal(byte[] arg0, int arg1, int arg2)
			throws IllegalBlockSizeException, BadPaddingException
	{
		return null;
	}

	protected int engineDoFinal(byte[] arg0, int arg1, int arg2, byte[] arg3, int arg4)
			throws ShortBufferException, IllegalBlockSizeException, BadPaddingException 
	{
		return 0;
	}

	protected int engineGetBlockSize() 
	{
		return 0;
	}

	protected byte[] engineGetIV() 
	{
		return null;
	}

	protected int engineGetOutputSize(int arg0) 
	{
		return 0;
	}

	protected AlgorithmParameters engineGetParameters() 
	{
		return null;
	}

	protected void engineInit(int mode, Key key, SecureRandom rnd) 
			throws InvalidKeyException 
	{
		if (mode == Cipher.ENCRYPT_MODE)
		{
			if (!(key instanceof DGKPublicKey))
			{
				throw new InvalidKeyException("I didn't get a DGKPublicKey.");
			}
			else
			{
				
			}
		}
		else if (mode == Cipher.DECRYPT_MODE)
		{
			if (!(key instanceof DGKPrivateKey))
			{
				throw new InvalidKeyException("I didn't get a DGKPrivateKey.");
			}
			else
			{
				
			}
		}
	}

	protected void engineInit(int arg0, Key arg1, AlgorithmParameterSpec arg2, SecureRandom arg3)
			throws InvalidKeyException, InvalidAlgorithmParameterException 
	{
		engineInit(arg0, arg1, arg3);
	}

	protected void engineInit(int arg0, Key arg1, AlgorithmParameters arg2, SecureRandom arg3)
			throws InvalidKeyException, InvalidAlgorithmParameterException 
	{
		engineInit(arg0, arg1, arg3);
	}

	protected void engineSetMode(String arg0) 
			throws NoSuchAlgorithmException 
	{
		throw new NoSuchAlgorithmException("DGK supports no modes.");
	}

	protected void engineSetPadding(String arg0) 
			throws NoSuchPaddingException
	{
		throw new NoSuchPaddingException("DGK supports no padding.");
	}

	protected byte[] engineUpdate(byte[] arg0, int arg1, int arg2) 
	{
		return null;
	}

	protected int engineUpdate(byte[] arg0, int arg1, int arg2, byte[] arg3, int arg4) 
			throws ShortBufferException 
	{
		return 0;
	}
	
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
		for (int i = 0; i < pubKey.u; i++)
		{
			test = DGKOperations.encrypt(pubKey, (long)i);
			testDecrypt = DGKOperations.decrypt(privKey, test);
			if (i==testDecrypt)
			{
				//System.out.println("SUCCESS AT ENCRYPT/DECRYPT: " + i);
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


	public static BigInteger encrypt(DGKPublicKey pubKey, BigInteger plaintext)
	{
		return encrypt(pubKey, plaintext.longValue());
	}
	
	public static BigInteger encrypt(long plaintext, DGKPublicKey pubKey)
	{
		return encrypt(pubKey, plaintext);
	}

	public static BigInteger encrypt(DGKPublicKey pubKey, long plaintext)
	{
		BigInteger ciphertext;
		if (plaintext == -1)
		{
			//System.err.println("Exception not thrown this time...I hope you are using Protocol 1/Modified Protocol 3");
		}
		else if (plaintext < 0)
		{
			throw new IllegalArgumentException("Encryption Invalid Parameter: the plaintext is not in Zu (plaintext < 0)"
				+ " value of Plain Text is: " + plaintext);
		}
		else if (plaintext >= pubKey.u)
		{
			throw new IllegalArgumentException("Encryption Invalid Parameter: the plaintext is not in Zu"
			+ " (plaintext >= U) value of Plain Text is: " + plaintext);
		}

		// If it is null, just fill the HashMap to avoid Null Pointer!
		if (pubKey.gLUT.get(plaintext) == null)
		{
			// Overwrite the HashMap
			pubKey.gLUT.put(plaintext, pubKey.g.modPow(BigInteger.valueOf(plaintext), pubKey.n));
			//first part = g^m (mod n)
		}

		// Generate 2*t bit random number
		BigInteger r = NTL.generateXBitRandom(2 * pubKey.t);
		r = r.setBit(2 * pubKey.t - 1);

		//First part = g^m
		BigInteger firstpart = pubKey.gLUT.get(plaintext);
		BigInteger secondpart = BigInteger.ONE;

		BigInteger tempH;
		for(long i = 0; i < r.bitLength(); ++i)
		{
			//second part = h^r
			if(NTL.bit(r, i) == 1)
			{
				tempH = pubKey.hLUT.get(i);
				if(tempH == null)
				{
					// e = 2^i (mod n)
					// f(i) = h^{2^i}(mod n)	
					BigInteger e = new BigInteger("2").modPow(BigInteger.valueOf(i), pubKey.n);
					pubKey.hLUT.put(i, pubKey.h.modPow(e, pubKey.n));
				}
				secondpart = secondpart.multiply(tempH);
			}
		}
		//System.out.println("Value of Second Part: " + secondpart);
		ciphertext = NTL.POSMOD(firstpart.multiply(secondpart), pubKey.n);
		return ciphertext;
	}
	
	public static BigInteger decrypt(BigInteger ciphertext, DGKPrivateKey privKey)
	{
		return BigInteger.valueOf(decrypt(privKey, ciphertext));
	}

	public static long decrypt(DGKPrivateKey privKey, BigInteger ciphertext)
	{
		if (ciphertext.signum() == -1)
		{
			throw new IllegalArgumentException("decryption Invalid Parameter : the cipher text is not in Zn, "
			+ "value of cipher text is: (c < 0): " + ciphertext);
		}
		if(ciphertext.compareTo(privKey.n) == 1)
		{
			throw new IllegalArgumentException("decryption Invalid Parameter : the cipher text is not in Zn,"
			+ " value of cipher text is: (c > n): " + ciphertext);
		}

		BigInteger decipher =  NTL.POSMOD(ciphertext, privKey.p).modPow(privKey.vp, privKey.p);
		/*
			c = g^m * h^r (mod n)
			c^vp (mod p) = g^{vp*m} (mod p)
			Because h^{vp} (mod p) = 1
		 */
		long plain = -1;
		try
		{
			plain = privKey.LUT.get(decipher);
		}
		catch (NullPointerException nfe)
		{
			System.err.println("Issue: DGK Public/Private Key mismatch! OR Using non-DGK encrpyted value!");
			nfe.printStackTrace();
		}
		return plain;
	}

	//[a] * [b] = [a * b]
	public static BigInteger add(DGKPublicKey pubKey, BigInteger a, BigInteger b)
	{
		if (a.signum() ==-1 || a.compareTo(pubKey.n) == 1)
		{
			throw new IllegalArgumentException("DGKAdd Invalid Parameter a: at least one of the ciphertext is not in Zn: " + a);
		}
		else if (b.signum() ==-1 || b.compareTo(pubKey.n) == 1)
		{
			throw new IllegalArgumentException("DGKAdd Invalid Parameter b: at least one of the ciphertext is not in Zn: " + b);
		}
		return a.multiply(b).mod(pubKey.n);
	}

	// [a]/[b] = [a - b]
	public static BigInteger subtract(DGKPublicKey pubKey, BigInteger a, BigInteger b)
	{
		BigInteger minus_b = multiply(pubKey, b, pubKey.u - 1);
		return add(pubKey, a, minus_b);
	}

	// cipher a * Plain text
	public static BigInteger multiply(DGKPublicKey pubKey, BigInteger cipher, long plaintext)
	{
		return multiply(pubKey, cipher, BigInteger.valueOf(plaintext));
	}

	public static BigInteger multiply(DGKPublicKey pubKey, BigInteger cipher, BigInteger plaintext)
	{
		if (cipher.signum() == -1)
		{
			throw new IllegalArgumentException("DGKMultiply Invalid Parameter: the ciphertext is not in Zn: " + cipher);
		}
		else if(cipher.compareTo(pubKey.n) == 1)
		{
			throw new IllegalArgumentException("DGKMultiply Invalid Parameter: the ciphertext is not in Zn: " + cipher);
		}

		if(plaintext.compareTo(pubKey.bigU) == 1)
		{
			throw new IllegalArgumentException("DGKMultiply Invalid Parameter:  the plaintext is not in Zu: " + pubKey.bigU);
		}
		return cipher.modPow(plaintext, pubKey.n);
	}
	
	public static BigInteger divide(DGKPublicKey pubKey, BigInteger cipher, BigInteger plaintext)
	{
		if (cipher.signum() == -1)
		{
			throw new IllegalArgumentException("DGKDivide Invalid Parameter: the ciphertext is not in Zn: " + cipher);
			/*
			System.err.println("ERROR SPOTTED: CIPHER TEXT IS NEGATIVE (DGKMULTIPLY)");
			cipher = NTL.POSMOD(cipher,n);
			*/
		}
		else if(cipher.compareTo(pubKey.n) == 1)
		{
			throw new IllegalArgumentException("DGKDivide Invalid Parameter: the ciphertext is not in Zn: " + cipher);
			/*
			System.err.println("ERROR SPOTTED: CIPHER TEXT IS > N (DGKMULTIPLY)");
			cipher.mod(n);
			*/
		}
		if(plaintext.compareTo(pubKey.bigU) == 1)
		{
			throw new IllegalArgumentException("DGKDivide Invalid Parameter: the plaintext is not in Zu: " + pubKey.bigU);
		}
		//[x]^(d^{-1})
		return cipher.modPow(plaintext.modInverse(pubKey.n), pubKey.n);
	}
	
	public static BigInteger divide(DGKPublicKey pubKey, BigInteger cipher, long plaintext)
	{
		return divide(pubKey, cipher, BigInteger.valueOf(plaintext));
	}
	
	public static BigInteger sum (DGKPublicKey pubKey, BigInteger [] parts)
	{
		BigInteger sum = DGKOperations.encrypt(pubKey, 0);
		for (int i = 0; i < parts.length; i++)
		{
			sum = add(pubKey, sum, parts[i]);
		}
		return sum;
	}
	
	public static BigInteger sum (DGKPublicKey pubKey, BigInteger [] parts, int limit)
	{
		BigInteger sum = DGKOperations.encrypt(pubKey, 0);
		if (limit > parts.length)
		{
			return sum(pubKey, parts);
		}
		else if(limit <= 0)
		{
			return sum;
		}
		for (int i = 0; i < limit; i++)
		{
			sum = add(pubKey, sum, parts[i]);
		}
		return sum;
	}
}//END OF CLASS