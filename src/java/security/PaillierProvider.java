package java.security;

public class PaillierProvider extends Provider 
{
	private static final long serialVersionUID = -6926028291417830360L;

	public PaillierProvider() 
	{
		super("Paillier", 1.0, "hi");
		put("KeyPairGenerator.Paillier",
				"src.paillier.crypto.PaillierKeyPairGenerator");
		put("Cipher.PaillierHP",
				"src.paillier.crypto.PaillierHomomorphicCipher");
		put("Cipher.Paillier", "src.paillier.crypto.PaillierCipher");
	}
}