package java.security;

import java.math.BigInteger;
import java.security.PaillierPK;
import java.security.PaillierSK;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

public class Paillier extends CipherSpi
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

	protected void engineInit(int arg0, Key arg1, SecureRandom arg2) 
			throws InvalidKeyException 
	{
		
	}

	protected void engineInit(int arg0, Key arg1, AlgorithmParameterSpec arg2, SecureRandom arg3)
			throws InvalidKeyException, InvalidAlgorithmParameterException 
	{
	
	}

	protected void engineInit(int arg0, Key arg1, AlgorithmParameters arg2, SecureRandom arg3)
			throws InvalidKeyException, InvalidAlgorithmParameterException 
	{
		
	}

	protected void engineSetMode(String arg0) 
			throws NoSuchAlgorithmException 
	{

	}

	protected void engineSetPadding(String arg0) 
			throws NoSuchPaddingException
	{

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
	
	// Compute ciphertext = (mn+1)r^n (mod n^2) in two stages: (mn+1) and (r^n).
	public static BigInteger encrypt(BigInteger plaintext, PaillierPK pk)
	{
		BigInteger randomness = new BigInteger(pk.k1, new SecureRandom());
		BigInteger tmp1 = plaintext.multiply(pk.n).add(BigInteger.ONE).mod(pk.modulus);
		BigInteger tmp2 = randomness.modPow(pk.n, pk.modulus);
		BigInteger ciphertext = tmp1.multiply(tmp2).mod(pk.modulus);
		return ciphertext;
	}
	
	public static BigInteger encrypt(long plaintext, PaillierPK pk)
	{
		return encrypt(BigInteger.valueOf(plaintext), pk);
	}

	// Compute plaintext = L(cipherText^(lambda) mod n^2) * mu mod n
	public static BigInteger decrypt(BigInteger ciphertext, PaillierSK sk)
	{
		// L(u) = (u-1)/n
		return L(ciphertext.modPow(sk.lambda, sk.modulus), sk.n).multiply(sk.mu).mod(sk.n);
	}

	// On input two encrypted values, returns an encryption of the sum of the values
	public static BigInteger add(BigInteger ciphertext1, BigInteger ciphertext2, PaillierPK pk)
	{
		//(Cipher1 * Cipher 2 (mod N)
		return ciphertext1.multiply(ciphertext2).mod(pk.modulus);
	}
	
	public static BigInteger summation(BigInteger [] values, PaillierPK pk)
	{
		BigInteger ciphertext = values[0];
		for (int i = 1; i < values.length; i++)
		{
			ciphertext = ciphertext.multiply(values[i]).mod(pk.modulus);
		}
		return ciphertext;
	}
	
	public static BigInteger summation(BigInteger [] values, PaillierPK pk, int limit)
	{
		if (limit > values.length)
		{
			return summation(values, pk);
		}
		BigInteger ciphertext = values[0];
		for (int i = 1; i < values.length; i++)
		{
			ciphertext = ciphertext.multiply(values[i]).mod(pk.modulus);
		}
		return ciphertext;
	}

	public static BigInteger subtract(BigInteger ciphertext1, BigInteger ciphertext2, PaillierPK pk)
	{
		ciphertext2 = Paillier.multiply(ciphertext2, -1, pk);
		BigInteger ciphertext = ciphertext1.multiply(ciphertext2).mod(pk.modulus);
		return ciphertext;
	}

	// On input an encrypted value x and a scalar c, returns an encryption of cx.
	public static BigInteger multiply(BigInteger ciphertext1, BigInteger scalar, PaillierPK pk)
	{
		BigInteger ciphertext = ciphertext1.modPow(scalar, pk.modulus);
		return ciphertext;
	}

	public static BigInteger multiply(BigInteger ciphertext1, long scalar, PaillierPK pk)
	{
		return multiply(ciphertext1, BigInteger.valueOf(scalar), pk);
	}

	/*
	 * Please note: Divide will only work correctly on perfect divisor
	 * 2|20, it will work.
	 * if you try 3|20, it will NOT work and you will get a wrong answer!
	 * 
	 * If you want to do 3|20, you MUST use a division protocol from Veugen paper
	 */
	public static BigInteger divide(BigInteger ciphertext, long divisor, PaillierPK pk)
	{
		return divide(ciphertext, BigInteger.valueOf(divisor), pk);
	}
	
	public static BigInteger divide(BigInteger ciphertext, BigInteger divisor, PaillierPK pk)
	{
		divisor = divisor.modInverse(pk.modulus);
		return multiply(ciphertext, divisor, pk);
	}

	// L(u)=(u-1)/n
	private static BigInteger L(BigInteger u, BigInteger n)
	{
		return u.subtract(BigInteger.ONE).divide(n);
	}

	public static BigInteger reRandomize(BigInteger ciphertext, PaillierPK pk)
	{
		return Paillier.add(ciphertext, Paillier.encrypt(BigInteger.ZERO, pk), pk);
	}

}