
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.net.*;
import java.io.*;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Scanner;


public class ChatClient implements Runnable
{  
    private Socket socket              = null;
    private Thread thread              = null;
    private DataInputStream  console   = null;
    private DataOutputStream streamOut = null;
    private ChatClientThread client    = null;

    private PrivateKey privateKey = null;
    private PublicKey publicKey = null;

    public ChatClient(String serverName, int serverPort)
    {  
        System.out.println("Establishing connection to server...");
        
        try
        {
            // Establishes connection with server (name and port)
            socket = new Socket(serverName, serverPort);
            System.out.println("Connected to server: " + socket);
            if (handShake()) {
                start();
            } else {
                System.out.println("Terminating.");
                socket.close();
            }
        }
        
        catch(UnknownHostException uhe)
        {  
            // Host unkwnown
            System.out.println("Error establishing connection - host unknown: " + uhe.getMessage()); 
        }
      
        catch(IOException ioexception)
        {  
            // Other error establishing connection
            System.out.println("Error establishing connection - unexpected exception: " + ioexception.getMessage()); 
        }
        
   }
    
   public void run()
   {  
       while (thread != null)
       {  
           try
           {  
               // Sends message from console to server
               streamOut.writeUTF(console.readLine());
               streamOut.flush();
           }
         
           catch(IOException ioexception)
           {  
               System.out.println("Error sending string to server: " + ioexception.getMessage());
               stop();
           }
       }
    }
    
    
    public void handle(String msg)
    {  
        // Receives message from server
        if (msg.equals(".quit"))
        {  
            // Leaving, quit command
            System.out.println("Exiting...Please press RETURN to exit ...");
            stop();
        }
        else
            // else, writes message received from server to console
            System.out.println(msg);
    }

    @SuppressWarnings("unchecked")
    private boolean loadKeys() {
        DataInputStream reader = new DataInputStream(System.in);
        FileInputStream fis = null;
        boolean fileExists = true;
        DataInputStream dis = new DataInputStream(System.in);
        byte[] password = new byte[32];
        FileOutputStream fos = null;
        ObjectOutputStream oos = null;
        ObjectInputStream ois = null;

        // Read username and password
        String keyFile;
          try{  System.out.println("Insert username: ");
              String username = reader.readLine();
            System.out.println("Insert password: ");
            dis.read(password, 0, 32);
            keyFile = username+".keys";
        } catch (IOException e) {
              System.out.println("Something went horribly wrong. We're soory.");
              return false;
        }

        // Check if key file exists
        try {
            fis = new FileInputStream(keyFile);
        } catch (IOException e) {
            System.out.println("Creating new key file.");
        }

        // Key file doesn't exist
        if(fis == null) {
            fileExists = false;

            // create new key file
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
                ArrayList<byte[]> keyList = new ArrayList<>();

                SecretKeySpec spec = new SecretKeySpec(password, "AES");
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.ENCRYPT_MODE, spec);

                // add 2 client keys
                keyList.add(cipher.doFinal(privateKey.getEncoded()));
                keyList.add(cipher.doFinal(publicKey.getEncoded()));

                oos.writeObject(keyList);
            } catch (NoSuchAlgorithmException|NoSuchPaddingException |InvalidKeyException|IllegalBlockSizeException |BadPaddingException e) {
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
                ArrayList<byte[]> keyList = (ArrayList<byte[]>)ois.readObject();
                KeyFactory kf = KeyFactory.getInstance("RSA");

                SecretKeySpec spec = new SecretKeySpec(password, "AES");
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.DECRYPT_MODE, spec);

                privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(cipher.doFinal(keyList.get(0))));
                publicKey = kf.generatePublic(new X509EncodedKeySpec(cipher.doFinal(keyList.get(1))));

            } catch (NoSuchAlgorithmException|NoSuchPaddingException|InvalidKeyException|IllegalBlockSizeException|BadPaddingException|InvalidKeySpecException e) {
                if(fileExists) {
                    System.out.println("Wrong username or password. Try again.");
                } else {
                    System.out.println("Couldn't decrypt stored keys. Terminating.");
                }
                return false;
            } catch (IOException|ClassNotFoundException e) {
                System.out.println("Couldn't read key file. Terminating.");
                return false;
            }

        return true;
    }
    private boolean generateKeys(){
        // Generate key pair
        try {
            System.out.println("Generating key pair.");
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);

            KeyPair pair = keyGen.generateKeyPair();
            privateKey = pair.getPrivate();
            publicKey = pair.getPublic();
            System.out.println("Key pair generated.");
        } catch (Exception e) {
            System.out.println("Error generating key pair.");
            return false;
        }
        return true;
    }

    private boolean handShake() {
        if(loadKeys()) {
            // Send public key to server
            System.out.println("sends keysand receive keys");
        }
        else{
            System.out.println("Couldn't generate keys.");
            return false;
        }



        System.out.println("Handshake completed.");
        return true;
    }


    // Inits new client thread
    public void start() throws IOException
    {
        console = new DataInputStream(System.in);
        streamOut = new DataOutputStream(socket.getOutputStream());
        if (thread == null)
        {  
            client = new ChatClientThread(this, socket);
            thread = new Thread(this);                   
            thread.start();
        }
    }
    
    // Stops client thread
    public void stop()
    {  
        if (thread != null)
        {  
            thread.stop();  
            thread = null;
        }
        try
        {  
            if (console   != null)  console.close();
            if (streamOut != null)  streamOut.close();
            if (socket    != null)  socket.close();
        }
      
        catch(IOException ioe)
        {  
            System.out.println("Error closing thread..."); }
            client.close();  
            client.stop();
        }
   
    
    public static void main(String args[])
    {  
        ChatClient client = null;
        if (args.length != 2)
            // Displays correct usage syntax on stdout
            System.out.println("Usage: java ChatClient host port");
        else
            // Calls new client
            client = new ChatClient(args[0], Integer.parseInt(args[1]));
    }
    
}

class ChatClientThread extends Thread
{  
    private Socket           socket   = null;
    private ChatClient       client   = null;
    private DataInputStream  streamIn = null;

    public ChatClientThread(ChatClient _client, Socket _socket)
    {  
        client   = _client;
        socket   = _socket;
        open();  
        start();
    }
   
    public void open()
    {  
        try
        {  
            streamIn  = new DataInputStream(socket.getInputStream());
        }
        catch(IOException ioe)
        {  
            System.out.println("Error getting input stream: " + ioe);
            client.stop();
        }
    }
    
    public void close()
    {  
        try
        {  
            if (streamIn != null) streamIn.close();
        }
      
        catch(IOException ioe)
        {  
            System.out.println("Error closing input stream: " + ioe);
        }
    }
    
    public void run()
    {  
        while (true)
        {   try
            {  
                client.handle(streamIn.readUTF());
            }
            catch(IOException ioe)
            {  
                System.out.println("Listening error: " + ioe.getMessage());
                client.stop();
            }
        }
    }
}

