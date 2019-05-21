package java.security;

public class DGKProvider extends Provider
{
	private static final long serialVersionUID = 7535524512688509040L;

	public DGKProvider() 
	 {
		 super("DGK", 1.0, "DGK v1.0");
		 put("KeyGenerator.DGK", DGKGenerator.class.getName());
		 put("Cipher.DGK", DGKOperations.class.getName());
	 }
}
