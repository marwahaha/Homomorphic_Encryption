package security.paillier;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.PrivateKey;

public class PaillierPrivateKey implements Serializable, PrivateKey
{
	private static final long serialVersionUID = -3342551807566493368L;

	// k1 is the security parameter. It is the number of bits in n.
    private final int key_size;
    
    final BigInteger n;
    final BigInteger modulus;
    
    final BigInteger lambda;
    final BigInteger mu;
    
    public PaillierPrivateKey(int key_size, BigInteger n, BigInteger mod, 
    		BigInteger lambda, BigInteger mu)
    {
        this.key_size = key_size;
        this.n = n;
        this.modulus = mod;
        this.lambda = lambda;
        this.mu = mu;
    }
  
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
    	answer += "key_size = " + key_size + ", " + '\n';
    	answer += "n = " + n + ", " + '\n';
    	answer += "modulus = " + modulus + '\n';
        return answer;
	}

	public int get_Keysize() 
	{
		return key_size;
	}
}