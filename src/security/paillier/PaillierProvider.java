package security.paillier;

import java.security.Provider;

public class PaillierProvider extends Provider 
{
	private static final long serialVersionUID = -6926028291417830360L;

	public PaillierProvider() 
	{
		// Sometimes 1.9 needs to be a String value???
		super("Paillier", 1.0, "Paillier v 1.0");
		put("KeyPairGenerator.Paillier", PaillierKeyPairGenerator.class.getName());
		put("Cipher.Paillier", PaillierCipher.class.getName());
	}
}