package security.paillier;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.PublicKey;

public class PaillierPublicKey implements PublicKey, Serializable
{
	// k1 is the security parameter. It is the number of bits in n.
	public final int keysize;
	
	// n = pq is a product of two large primes (such N is known as RSA modulous)
    public final BigInteger n;
    final BigInteger modulus;
    
    public PaillierPublicKey(int keysize, BigInteger n, BigInteger modulus)
    {
    	this.keysize = keysize;
    	this.n = n;
    	this.modulus = modulus;
    }
    
    private static final long serialVersionUID = PublicKey.serialVersionUID;

    private void readObject(ObjectInputStream aInputStream) throws ClassNotFoundException,
            IOException
    {
        aInputStream.defaultReadObject();
    }

    private void writeObject(ObjectOutputStream aOutputStream) throws IOException
    {
        aOutputStream.defaultWriteObject();
    }

	public String getAlgorithm() 
	{
		return "Paillier";
	}

	public String getFormat() 
	{
		return "NONE";
	}

	public byte[] getEncoded() 
	{
		return null;
	}
	
    public String toString()
    {
    	String answer = "";
    	answer += "k1 = " + keysize + ", " + '\n';
    	answer += "n = " + n + ", " + '\n';
    	answer += "modulus = " + modulus + '\n';
        return answer;
    }
}