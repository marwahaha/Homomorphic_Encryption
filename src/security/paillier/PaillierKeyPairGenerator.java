package security.paillier;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;

public class PaillierKeyPairGenerator extends KeyPairGeneratorSpi 
{
	// k2 controls the error probability of the primality testing algorithm
	// (specifically, with probability at most 2^(-k2) a NON prime is chosen).
	private static int k2 = 40;
	private int keysize = 1024;
	private SecureRandom rnd = null;
	
	public void initialize(int keysize, SecureRandom random) 
	{
		this.rnd = random;
		this.keysize = keysize/2;
	}

	public KeyPair generateKeyPair() 
	{
		if (rnd == null)
		{
			rnd = new SecureRandom();
		}
		
		// Chooses a random prime of length k2. The probability that
		// p is not prime is at most 2^(-k2)
		BigInteger p = new BigInteger(keysize, k2, rnd);
		BigInteger q = new BigInteger(keysize, k2, rnd);

		BigInteger n = p.multiply(q); // n = pq
		BigInteger modulus = n.multiply(n); // modulous = n^2
		
		PaillierPublicKey pk = new PaillierPublicKey(keysize * 2, n, modulus);

		// Modifications to the Private key
		BigInteger lambda = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
		BigInteger mu = lambda.modInverse(pk.n);
		PaillierPrivateKey sk = new PaillierPrivateKey(keysize * 2, n, modulus, lambda, mu);
		return new KeyPair(pk, sk);
	}
}
