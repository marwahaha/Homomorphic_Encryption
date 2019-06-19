package security.paillier;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.PrivateKey;

public class PaillierPrivateKey implements Serializable, PrivateKey
{
    // k1 is the security parameter. It is the number of bits in n.
    public int k1 = 1024;
    
    public final BigInteger n;
    public final BigInteger modulus;
    
    public final BigInteger lambda;
    public final BigInteger mu;
    
    public PaillierPrivateKey(int k1, BigInteger n, BigInteger mod, 
    		BigInteger lambda, BigInteger mu)
    {
        this.k1 = k1;
        this.n = n;
        this.modulus = mod;
        this.lambda = lambda;
        this.mu = mu;
    }
    
    private static final long serialVersionUID = PrivateKey.serialVersionUID;

    private void readObject(ObjectInputStream aInputStream)
            throws ClassNotFoundException,IOException
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
	
	// Omitting secret key parameters
	public String getString()
	{
    	String answer = "";
    	answer += "k1 = " + k1 + ", " + '\n';
    	answer += "n = " + n + ", " + '\n';
    	answer += "modulus = " + modulus + '\n';
        return answer;
	}
}