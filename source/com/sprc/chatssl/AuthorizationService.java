/**
	Tema 4 SPRC chatSSL
	@author Rizea Daniel
 */
package com.sprc.chatssl;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Scanner;
import java.util.StringTokenizer;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.TrustManager;

/**
 * A server class used to authenticate users and grant permissions to different clients based
 * on there certificate OU information and banned status
 * @author Rizea Daniel-Octavian
 *
 */

//organization servers that are supported
class ChatServerInfo{
	
	//servers name
	public String name;
	//server priority
	public int priority;
	
	public ChatServerInfo(String name, int priority){
		this.name = name;
		this.priority = priority;
	}
}

/* Class that runs the authorization service 
 * 
 */
public class AuthorizationService implements Runnable {

	/** Logger used by this class */
	private static final transient Logger logger = Logger.getLogger("");
	
	// variable that is tested for running conditions
	protected volatile boolean hasToRun = true;
	// server socket
	protected ServerSocket ss = null;
	
	// un pool de threaduri ce este folosit pentru executia secventelor de operatii corespunzatoare
	// conextiunilor cu fiecare client
	
	final protected ExecutorService pool;
	final private ThreadFactory tfactory;

	private ArrayList<ChatServerInfo> chatServers = null ;
	
	//a hash map with user names and system time in seconds when banning occuerd
	private static HashMap<String,Long> bannedUsers = null;
	
	//100 seconds banned interval
	private Long bannedInterval = 100L;
	
	//variables used to write and read using cryptography
	private static PBEKeySpec pbeKeySpec;
	private static PBEParameterSpec pbeParamSpec;
	private static SecretKeyFactory keyFac;
	private static CipherOutputStream cos;
	private static CipherInputStream cis;
	private static PrintWriter pwcis;
	
	/**
	 * Constructor.
	 * @param port on what the server will listen
	 * @throws Exception
	 */
	public AuthorizationService(int port) throws Exception {
		// set up key manager to do server authentication
		String store=System.getProperty("KeyStore");
		String passwd =System.getProperty("KeyStorePass");
		ss = createServerSocket(port, store, passwd);

		//create servers and attach priority 
		chatServers = new ArrayList<ChatServerInfo>();
		
		chatServers.add(new ChatServerInfo("management", 10));
		chatServers.add(new ChatServerInfo("it", 5));
		chatServers.add(new ChatServerInfo("accounting", 6));
		chatServers.add(new ChatServerInfo("hr", 6));
		
		tfactory = new DaemonThreadFactory();
		pool = Executors.newCachedThreadPool(tfactory);		
	}
	
	/**
	 * Metoda ce creaza un nou server socket folosind un anumit keystore si parola
	 * @param port: port to listen on
	 * @param store: the path to keystore file containing server key pair (private/public key); if <code>null</code> is passed 
	 * @param passwd: password needed to access keystore file
	 * @return a SSL Socket bound on port specified
	 * @throws IOException
	 */
	public static SSLServerSocket createServerSocket(int port, String keystore, String password) throws IOException {
		SSLServerSocketFactory ssf = null;
		SSLServerSocket ss = null;
		try {
			SSLContext ctx;
			KeyManagerFactory kmf;
			KeyStore ks;
			ctx = SSLContext.getInstance("SSL");
			kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
			ks = KeyStore.getInstance(KeyStore.getDefaultType());
			FileInputStream is = new FileInputStream(keystore);
			ks.load(is, password.toCharArray());
			kmf.init(ks, password.toCharArray());
			if (logger.isLoggable(Level.FINER))
				logger.log(Level.FINER, "Server keys loaded");

			ctx.init(kmf.getKeyManagers(),new TrustManager[] {new EasyX509TrustManager(ks)}, new java.security.SecureRandom());
			
			ssf = ctx.getServerSocketFactory();
			if (logger.isLoggable(Level.FINER)) {
				logger.log(Level.FINER, "Creating SSocket");
			}
			ss = (SSLServerSocket) ssf.createServerSocket();
			
			if (logger.isLoggable(Level.FINER)) {
				logger.log(Level.FINER, "SSocket created!");
			}

			if (logger.isLoggable(Level.FINER)) {
				logger.log(Level.FINER, "SSocket binding on port " + port);
			}
			ss.bind(new InetSocketAddress(port));
			if (logger.isLoggable(Level.FINER)) {
				logger.log(Level.FINER, "SSocket bounded on port " + port);
			}
			// this socket will try to authenticate clients based on X.509 Certificates			
			ss.setNeedClientAuth(true);
			
			if (logger.isLoggable(Level.FINER)) {
				logger.log(Level.FINER, "SSocket FINISHED ok! Bounded on " + port);
			}

		} catch (Throwable t) {
			if (logger.isLoggable(Level.FINER)) {
				logger.log(Level.FINER, "Got Exception", t);
			}
			t.printStackTrace();
			throw new IOException(t.getMessage());
		}
		return ss;
	}

	/**
	 * Metoda run ... accepta conexiuni si initiaza noi threaduri pentru fiecare conexiune in parte
	 */
	public void run() {
		if (logger.isLoggable(Level.INFO))
			logger.log(Level.INFO, "ChatServerSSL entering main loop ... ");
		while (hasToRun) {
			try {
				
				Socket s = ss.accept();
				
			    s.setTcpNoDelay(true);	
				//add the client connection to connection pool
				pool.execute(new ClientThread(s));
				if (logger.isLoggable(Level.INFO))
					logger.log(Level.INFO, "New client connection added to connection-pool",s);
			} catch (Throwable t) {
				t.printStackTrace();
			}
		}
	}

	/**
	 * Metoda poate fi folosita pentru oprirea serverului
	 */
	public void stop() {
		hasToRun = false;
		try {
			ss.close();
		} catch (Exception ex) {}
		ss = null;
	}
	
	/**
	 * Custom thread factory used in connection pool
	 */
	private final class DaemonThreadFactory implements ThreadFactory {
		public Thread newThread(Runnable r) {
			Thread thread = new Thread(r);
			thread.setDaemon(true);
			return thread;
		}
	}
	
	/**
	 * Class that implemets ssl connection with a company's server
	 */
	private final class ClientThread implements Runnable {
		
		private BufferedReader br;
		private PrintWriter pw;
		private Socket s;

		
		public ClientThread(Socket s) {
			try {
				pw = new PrintWriter(new OutputStreamWriter(s.getOutputStream()));
				br = new BufferedReader(new InputStreamReader(s.getInputStream()));
				this.s = s;
			} catch (Exception e) { 
				
			System.out.println("Client thread creation");
			}
		}
		
		public void close() {
			if (br != null){
	            try {
	                br.close();
	            }catch(Throwable tt){
	            }
	        }
	        if (pw != null){
	            try {
	                pw.close();
	            }catch(Throwable tt){
	            }
	        }
	        if ( s != null){
	            try {
	                s.close();
	            } catch (Throwable t){
	            }
	        }
		}

		public void run() {
			// run indefinetely until exception
			String str;
			while (true) {
				try {
					
					//System.out.println("waiting for input");
					str = br.readLine();
					// simulate processing
					
					System.out.println("S-a primit |"+str+"|");
					if(str == null)
						break;
					
					
				}
				catch(Exception e){
					System.out.println("Error reading from console" + e.getMessage());
					break;
				}	
					
				String cmd = str;
				// iau primul cuvant
				int pos = str.indexOf(' ');
				if (pos != -1) {
					cmd = str.substring(0, pos);
					str = str.substring(pos + 1);
				} else {
					str = null;
				}
				
				//decide what action to take based on the parameters received
				
				if (cmd.toLowerCase().compareTo("authorize") == 0) {
					//get authorization for user
					
					//get desired depatment
					String department = str.substring(0, str.indexOf(' '));
					str = str.substring(str.indexOf(' ')+1);
					
					//get OU information
					String OU = str.substring(0, str.indexOf(' '));
					
					str = str.substring(str.indexOf(' ')+1);
					//get username
					String username = str;
					System.out.println("Authorize department request : " + department + " OU : " + OU + " username:" + username);
					
					Boolean banned = false;
					//verify if user is banned
					Long startBannedInterval;
					
					
					// verify if user is banned
					if(bannedUsers.get(username) != null){
						
						startBannedInterval = bannedUsers.get(username);
						if(startBannedInterval + bannedInterval < System.currentTimeMillis()/1000 ){
							bannedUsers.remove(username);
						}
						else
							banned = true;
					}
					
					//if banned then return elapsed time before user is unbanned
					if(banned == true){
						startBannedInterval = bannedUsers.get(username);
						pw.println("Error");
						pw.flush();
						pw.println("User is banned for "+ ( (startBannedInterval + bannedInterval) -System.currentTimeMillis()/1000)  +"seconds from any servers ");
						pw.flush();
					}
					else{
					
						//if user is not banned
						int i;
						int priorityUser = -1;
						int priorityRequestedDepartment = -1;
						
						//get associated priority for user
						for(i=0;i<chatServers.size();i++){
							System.out.println(chatServers.get(i).name+" "+OU+"|");
							if(OU.compareToIgnoreCase(chatServers.get(i).name) == 0){
								priorityUser = chatServers.get(i).priority;
								break;
								}
							}
						
						//get associated priority for user request
						for(i=0;i<chatServers.size();i++){
							if(department.compareToIgnoreCase(chatServers.get(i).name) == 0){
								priorityRequestedDepartment = chatServers.get(i).priority;
								break;
								}
							}
						
						
						System.out.println("User access priority: " + priorityUser + " Requested access priority: " + priorityRequestedDepartment);
						
						//if priority requested by user is less or equal to priority of user than grant access
							if(priorityRequestedDepartment <= priorityUser && priorityUser != -1 && priorityRequestedDepartment != -1){
								
								System.out.println("Access granted");
								pw.println("ok");
								pw.flush();
							}else
							{
								
								//else determine the error message 
								
								String errorMessage;
								if(priorityUser == -1)
									errorMessage = "Server Certificate OU :" + OU + " does not exist"; 
								else
								if(priorityRequestedDepartment == -1)
									errorMessage = "Requested department " + department + " does not exist";
								else
									errorMessage = "Access denied by server, user with certificate clearance to access " + OU + " can't access " + department;
								
								
								
								System.out.println("Access refused");
							
								pw.println("error");
								pw.flush();
							
								pw.println(errorMessage);
								pw.flush();
							}	
							//System.out.println("Good bye!");
					}
				}else 
				if(cmd.toLowerCase().compareTo("ban") == 0){
					//ban this user
					
					//get user name
					String username = str;
				
					bannedUsers.put(username, System.currentTimeMillis()/1000);
					System.out.println("Server banned user " + username + " at time " + System.currentTimeMillis()/1000);
					
					//write user to banned_list file
					StringBuffer textToPrint = new StringBuffer(username+ " " + System.currentTimeMillis()/1000);
					
					textToPrint.append(' ');
					
					//padding the text so %8 == 0 so it can be cripted 
					if((textToPrint.length())%16!=0){
						
						//System.out.println("Do padding");
						for(int i=0;i<(textToPrint.length())%16;i++)
							textToPrint.append(' ');
						
					
					}
					
					System.out.println("Padding length " +textToPrint.length());
					
					//printing the cripted text in a file
					pwcis.print(textToPrint);
					pwcis.flush();
				}					
	
			}

			close();
			
		}
	}
	
	
	public static void main(String args[]) {
		if (args == null || args.length < 1) {
			System.out.println("Nu a fost furnizat ca argument portul");
			return;
		}
		
		//		Salt
		byte[] salt = { (byte) 0xc7, (byte) 0x73, (byte) 0x21, (byte) 0x8c, (byte) 0x7e, (byte) 0xc8, (byte) 0xee, (byte) 0x99 };
		//		Iteration count
		int count = 20;
		//		Create PBE parameter set
		pbeParamSpec = new PBEParameterSpec(salt, count);
		//		convert password into a SecretKey object, using a PBE key
		//		factory.
		
		try {
			
			char[] passwd = {'O','C','T','A','V'};
			
			pbeKeySpec = new PBEKeySpec(passwd);
			keyFac = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
			SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);
			//			Create PBE Cipher
			Cipher pbeCipher = Cipher.getInstance("PBEWithMD5AndDES");
			Cipher decCipher = Cipher.getInstance("PBEWithMD5AndDES");

			//			Initialize PBE Cipher with key and parameters
			pbeCipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);
			decCipher.init(Cipher.DECRYPT_MODE, pbeKey, pbeParamSpec);
			
		
			//restore on startup banned list from file banned_list 
			System.out.println("Load banned list");
			
			bannedUsers = new HashMap<String, Long>();	
			try{
				cis = new CipherInputStream(new FileInputStream("banned_list"),decCipher);		
				byte[] dec = new byte[10000];
				cis.read(dec);
				String dectext = new String(dec,"UTF8");
			
				System.out.println("Text decriptat" + dectext+"|");
				Scanner s = new Scanner(dectext);
				
				StringTokenizer stoken = new StringTokenizer(dectext);
				
				while(stoken.hasMoreTokens()){
					String username = stoken.nextToken(" ");
				
					String time = stoken.nextToken();
					
					System.out.println("user " +username+time+"|");
					Long bannedTime = Long.parseLong(time);
					
					bannedUsers.put(username, bannedTime);
					System.out.println("Banned user " + username + " time when he was banned " + bannedTime);

				}
				cis.close();
				
			}catch(Exception e){
				System.out.println("No file banned_list exists, it will be created " + e.getMessage());
			}
			
			cos = new CipherOutputStream(new FileOutputStream("banned_list"),pbeCipher);
			pwcis = new PrintWriter(new OutputStreamWriter(cos));
			
			} catch (Exception e) {
				System.out.println(e.getMessage());
			}
			
			
		
		try {
			int port = Integer.parseInt(args[0]);
			(new Thread(new AuthorizationService(port))).start();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
