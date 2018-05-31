
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.net.*;
import java.io.*;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;


public class ChatServer implements Runnable
{  
	private ChatServerThread clients[] = new ChatServerThread[20];
	private ServerSocket server_socket = null;
	private static final String keyFile = "Serverkeys.keys";
	PrivateKey privateKey = null;
	PublicKey publicKey = null;
	private Thread thread = null;
	private int clientCount = 0;

	public ChatServer(int port)
    	{
			if (!loadKeys()) {
				return;
			}
		try
      		{  
            		// Binds to port and starts server
			System.out.println("Binding to port " + port);
            		server_socket = new ServerSocket(port);  
            		System.out.println("Server started: " + server_socket);
            		start();
        	}
      		catch(IOException ioexception)
      		{  
            		// Error binding to port
            		System.out.println("Binding error (port=" + port + "): " + ioexception.getMessage());
        	}
    	}
    
    	public void run()
    	{  
        	while (thread != null)
        	{  
            		try
            		{  
                		// Adds new thread for new client
                		System.out.println("Waiting for a client ..."); 
                		addThread(server_socket.accept()); 
            		}
            		catch(IOException ioexception)
            		{
                		System.out.println("Accept error: " + ioexception); stop();
            		}
        	}
    	}
    
   	public void start()
    	{  
        	if (thread == null)
        	{  
            		// Starts new thread for client
            		thread = new Thread(this); 
            		thread.start();
        	}
    	}
    
    	public void stop()
    	{  
        	if (thread != null)
        	{
            		// Stops running thread for client
            		thread.stop(); 
            		thread = null;
        	}
    	}
   
    	private int findClient(int ID)
    	{  
        	// Returns client from id
        	for (int i = 0; i < clientCount; i++)
            		if (clients[i].getID() == ID)
                		return i;
        	return -1;
    	}
    
    	public synchronized void handle(int ID, String input)
    	{  
        	if (input.equals(".quit"))
            	{  
                	int leaving_id = findClient(ID);
                	// Client exits
                	clients[leaving_id].send(".quit");
                	// Notify remaing users
                	for (int i = 0; i < clientCount; i++)
                    		if (i!=leaving_id)
                        		clients[i].send("Client " +ID + " exits..");
                	remove(ID);
            	}
        	else
            		// Brodcast message for every other client online
            		for (int i = 0; i < clientCount; i++)
                		clients[i].send(ID + ": " + input);   
    	}

	@SuppressWarnings("unchecked")
	private boolean loadKeys() {
		FileInputStream fis = null;
		ObjectInputStream ois;
		System.out.println("Insert password: ");
		DataInputStream dis = new DataInputStream(System.in);
		byte[] password = new byte[32];

		// Read password and check if key file exists
		try {
			int ignore = dis.read(password, 0, 32);
			fis = new FileInputStream(keyFile);
		} catch (IOException e) {
			System.out.println("Generating new key file.");
		}
		// Key file doesn't exist
		if (fis == null) {
			FileOutputStream fos;
			ObjectOutputStream oos;
			// Generate new key file
			try {
				fos = new FileOutputStream(keyFile);
				oos = new ObjectOutputStream(fos);
			} catch (IOException e) {
				System.out.println("Couldn't create key file. Terminating.");
				return false;
			}

			generateKeys();
			// Create new array list for keys, where each entry is encrypted with AES and the given password
			try {

				ArrayList<byte[]> serverkeylist = new ArrayList<>();


				SecretKeySpec spec = new SecretKeySpec(password, "AES");
				Cipher cipher = Cipher.getInstance("AES");
				cipher.init(Cipher.ENCRYPT_MODE, spec);

				// add server keys
				serverkeylist.add(cipher.doFinal(privateKey.getEncoded()));
				serverkeylist.add(cipher.doFinal(publicKey.getEncoded()));

				oos.writeObject(serverkeylist);
			} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
				System.out.println("Couldn't encrypt newly generated keys. Terminating");
				return false;
			} catch (IOException e) {
				System.out.println("Couldn't store newly generated keys in file. Terminating.");
				return false;
			}
		}

		// Try and open the file again
		try {
			fis = new FileInputStream(keyFile);
			ois = new ObjectInputStream(fis);
		} catch (IOException e) {
			System.out.println("Couldn't read key file. Terminating.");
			return false;
		}

		try {
			ArrayList<byte[]> serverkeylist = (ArrayList<byte[]>)ois.readObject();
			KeyFactory kf = KeyFactory.getInstance("RSA");

			SecretKeySpec spec = new SecretKeySpec(password, "AES");
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.DECRYPT_MODE, spec);

			privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(cipher.doFinal(serverkeylist.get(0))));
			publicKey = kf.generatePublic(new X509EncodedKeySpec(cipher.doFinal(serverkeylist.get(1))));

		} catch (NoSuchAlgorithmException|NoSuchPaddingException|InvalidKeyException|IllegalBlockSizeException|BadPaddingException|InvalidKeySpecException e) {
			System.out.println("Couldn't decrypt stored keys. Terminating.");
			return false;
		} catch (IOException|ClassNotFoundException e) {
			System.out.println("Couldn't read key file. Terminating.");
			return false;
		}

		return true;
	}

	private boolean generateKeys() {
		// Generate key pair
		try {
			System.out.println("Generating key pair.");
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(2048);

			KeyPair keypair = keyGen.generateKeyPair();
			privateKey = keypair.getPrivate();
			publicKey = keypair.getPublic();
			System.out.println("Key pair generated.");
		} catch (Exception e) {
			System.out.println("Error generating key pair.");
			return false;
		}
		return true;
	}

    	public synchronized void remove(int ID)
    	{  
        	int pos = findClient(ID);
      
       	 	if (pos >= 0)
        	{  
            		// Removes thread for exiting client
            		ChatServerThread toTerminate = clients[pos];
            		System.out.println("Removing client thread " + ID + " at " + pos);
            		if (pos < clientCount-1)
                		for (int i = pos+1; i < clientCount; i++)
                    			clients[i-1] = clients[i];
            		clientCount--;
         
            		try
            		{  
                		toTerminate.close(); 
            		}
         
            		catch(IOException ioe)
            		{  
                		System.out.println("Error closing thread: " + ioe); 
            		}
         
            		toTerminate.stop(); 
        	}
    	}
    
    	private void addThread(Socket socket)
    	{  
    	    	if (clientCount < clients.length)
        	{  
            		// Adds thread for new accepted client
            		System.out.println("Client accepted: " + socket);
            		clients[clientCount] = new ChatServerThread(this, socket);
         
           		try
            		{  
                		clients[clientCount].open(); 
                		clients[clientCount].start();  
                		clientCount++; 
            		}
            		catch(IOException ioe)
            		{  
               			System.out.println("Error opening thread: " + ioe); 
            		}
       	 	}
        	else
            		System.out.println("Client refused: maximum " + clients.length + " reached.");
    	}
    
    
	public static void main(String args[])
   	{  
        	ChatServer server = null;
        
        	if (args.length != 1)
            		// Displays correct usage for server
            		System.out.println("Usage: java ChatServer port");
        	else
            		// Calls new server
            		server = new ChatServer(Integer.parseInt(args[0]));
    	}

}

class ChatServerThread extends Thread
{  
    private ChatServer       server    = null;
    private Socket           socket    = null;
    private int              ID        = -1;
    private DataInputStream  streamIn  =  null;
    private DataOutputStream streamOut = null;

   
    public ChatServerThread(ChatServer _server, Socket _socket)
    {  
        super();
        server = _server;
        socket = _socket;
        ID     = socket.getPort();
    }
    
    // Sends message to client
    public void send(String msg)
    {   
        try
        {  
            streamOut.writeUTF(msg);
            streamOut.flush();
        }
       
        catch(IOException ioexception)
        {  
            System.out.println(ID + " ERROR sending message: " + ioexception.getMessage());
            server.remove(ID);
            stop();
        }
    }
    
    // Gets id for client
    public int getID()
    {  
        return ID;
    }
   
    // Runs thread
    public void run()
    {  
        System.out.println("Server Thread " + ID + " running.");
      
        while (true)
        {  
            try
            {  
                server.handle(ID, streamIn.readUTF());
            }
         
            catch(IOException ioe)
            {  
                System.out.println(ID + " ERROR reading: " + ioe.getMessage());
                server.remove(ID);
                stop();
            }
        }
    }
    
    
    // Opens thread
    public void open() throws IOException
    {  
        streamIn = new DataInputStream(new 
                        BufferedInputStream(socket.getInputStream()));
        streamOut = new DataOutputStream(new
                        BufferedOutputStream(socket.getOutputStream()));
    }
    
    // Closes thread
    public void close() throws IOException
    {  
        if (socket != null)    socket.close();
        if (streamIn != null)  streamIn.close();
        if (streamOut != null) streamOut.close();
    }
    
}

