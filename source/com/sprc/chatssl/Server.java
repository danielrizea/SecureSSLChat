
package com.sprc.chatssl;

import java.io.BufferedReader;
import java.io.FileInputStream;
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
import java.util.Enumeration;
import java.util.Iterator;
import java.util.StringTokenizer;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.security.cert.X509Certificate;


/**
 * Class that stores informations regarding connection per client
 * @author Rizea Daniel
 *
 */
class ClientInfo{
	
	public Socket openSocket = null;
	public String username = "";
	public CertificateInfo clientCertificateInfo = null;
	public BufferedReader br = null;
	public PrintWriter pw = null;
	
	
	
	public ClientInfo(Socket os,String username,CertificateInfo certInfo){
		this.openSocket = os;
		this.username = username;
		this.clientCertificateInfo = certInfo;
		try{
			this.pw = new PrintWriter(new OutputStreamWriter(openSocket.getOutputStream()));
			this.br = new BufferedReader(new InputStreamReader(openSocket.getInputStream()));
		}catch(Exception e){
			System.out.println("Exceptie la creare pw si br");
		}
	}
}

/**
 * Class that simulates a server
 * name = : company department : management, it
 * has a list of clients attached to it
 * @author Rizea Daniel
 *
 */
class ChatServer{
	
	public ArrayList<ClientInfo> clients;
	public String name;
	
	public ChatServer(String name){
		this.name = name;
		clients = new ArrayList<ClientInfo>();
	}
	
}

/**
 * Server class that simulates multuple servers for each department.It accespts SSL connections
 * from clients that have certificates signed by MyCompany
 * @author Rizea Daniel
 *
 */

public class Server implements Runnable {
	
	/** Logger used by this class */
	private static final transient Logger logger = Logger.getLogger("");
	
	// variabila ce este folosita pentru testarea conditiei de oprire
	protected volatile boolean hasToRun = true;
	// socketul server
	protected ServerSocket ss = null;
	
	protected ServerSocket authorizationss = null;
	
	// un pool de threaduri ce este folosit pentru executia secventelor de operatii corespunzatoare
	// conextiunilor cu fiecare client
	final protected ExecutorService pool;
	final private ThreadFactory tfactory;
	
	/*  Pentru conexiunea cu serviciul de autorizare
	 */
	private BufferedReader brAuthorization;
	private PrintWriter pwAuthorization;
	private SSLSocket sAuthorizationConnection;
	
	//hashmap containing available servers;
	private ConcurrentHashMap<String, ChatServer> servers = null;

	//banned word list 
	public static String[] bannedWords={"bomba","bomb","teme in vacanta",":)"};
	
	
	/* Function get certificate information from string and return object CertificateInformation
	 * 
	 */
	public CertificateInfo getCertificateInformation(String infoString){
		
		CertificateInfo info = new CertificateInfo();
		String cer = "";
		String val = "";
		StringTokenizer st = new StringTokenizer(infoString, ",");
		//System.out.println("Here it is");
		while(st.hasMoreTokens()) {
			
		
			String token = st.nextToken();
		//	System.out.println("Tocken " + token);
			int pos = token.indexOf('=');
			
			//System.out.println("String " + pos);
			if(pos>0){
			
				
				if(token.charAt(0) == ' ')
					cer = token.substring(1,pos);
				else
					cer = token.substring(0,pos);
				
				val = token.substring(pos+1);
			//	System.out.println("Str" + cer + " " + val);
			if(cer.toLowerCase().compareTo("o") == 0){
				//System.out.println("O memorized");
				info.O = val;
			}else
				if(cer.toLowerCase().compareTo("cn") == 0){
					info.CN = val;
				//	System.out.println("CN memorized");
				}
				else
					if(cer.toLowerCase().compareTo("ou") == 0){
						info.OU = val;
					//	System.out.println("OU memorized");
					}
			}
		} 	
		
		
		return info; 
	}
	
	/*
	 * Establishes a connection with the authorization service
	 */
	public void createSSLAuthorizationConnection (String address, int port) throws Exception{

		// set up key manager to do server authentication
		String store=System.getProperty("KeyStore");
		String passwd =System.getProperty("KeyStorePass");

		SSLContext ctx;
		KeyManagerFactory kmf;
		KeyStore ks;
		char[] storepswd = passwd.toCharArray(); 
		ctx = SSLContext.getInstance("SSL");

		/* IBM or Sun vm ? */
		if ( System.getProperty("java.vm.vendor").toLowerCase().indexOf("ibm") != -1 ){
			kmf = KeyManagerFactory.getInstance("IBMX509","IBMJSSE");
		} else {
			kmf = KeyManagerFactory.getInstance("SunX509");
		}

		//parola keystore
		ks = KeyStore.getInstance("JKS");

		ks.load(new FileInputStream(store), storepswd);
		kmf.init(ks,storepswd);
		ctx.init(kmf.getKeyManagers(), new TrustManager[] {new EasyX509TrustManager(ks)}, null);
		SSLSocketFactory ssf = ctx.getSocketFactory();
		sAuthorizationConnection = (SSLSocket)ssf.createSocket();

		
		sAuthorizationConnection.connect(new InetSocketAddress(address, port));

		pwAuthorization = new PrintWriter(new OutputStreamWriter(sAuthorizationConnection.getOutputStream()));
		brAuthorization  = new BufferedReader(new InputStreamReader(sAuthorizationConnection.getInputStream()));

	} //createSSLConnection
	
	
	
	/**
	 * Constructor.
	 * @param port Port on witch the server will listen, authServicePort and authServiceHost where the authorization service is
	 * @throws Exception
	 */
	public Server(int port,int portAuthorizationService,String authorizationServiceHost) throws Exception {
		// set up key manager to do server authentication
		String store=System.getProperty("KeyStore");
		String passwd =System.getProperty("KeyStorePass");
		ss = createServerSocket(port, store, passwd);
		
		//create SSL connection with authorization service
		createSSLAuthorizationConnection(authorizationServiceHost, portAuthorizationService);
		
		servers = new ConcurrentHashMap<String, ChatServer>();
		
		//initialize available servers, here we have an example, only 4 departments, each with his server
		servers.put("management", new ChatServer("management"));
		servers.put("it", new ChatServer("it"));
		servers.put("accounting", new ChatServer("accounting"));
		servers.put("hr", new ChatServer("hr"));
	
		
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
			
				//get client's certificate information, specially the OU field
				SSLSession session = ((SSLSocket) s).getSession();
				X509Certificate[] cchain2 = session.getPeerCertificateChain();
			    CertificateInfo certInfo = getCertificateInformation(((X509Certificate) cchain2[0]).getSubjectDN().getName());
			    //create client info
			    ClientInfo client = new ClientInfo(s, certInfo.CN, certInfo);
			   
			    //System.out.println("User " + certInfo.CN + " Department" + certInfo.OU );
			    s.setTcpNoDelay(true);	
			    //add the client connection to connection pool
			    //pass client info to the thread that will manage the connection
			    pool.execute(new ClientThread(s,client));
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
	 * Clasa ce implementeaza functionalitatea conexiunii cu un anumit client
	 * @author Dobre Ciprian
	 *
	 */
	private final class ClientThread implements Runnable {
		
		private BufferedReader br;
		private PrintWriter pw;
		private Socket s;

		private ClientInfo clientInfo = null;
		
		public ClientThread(Socket s,ClientInfo clientInfo) {
			try {
				pw = new PrintWriter(new OutputStreamWriter(s.getOutputStream()));
				br = new BufferedReader(new InputStreamReader(s.getInputStream()));
				this.clientInfo = clientInfo;
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
					str = br.readLine();
					
					System.out.println("S-a citit |"+str+"|");
					if(str == null)
						break;	
				}
				catch(Exception e){
					System.out.println("Error reading from console" + e.getMessage());
					break;
				}
				
				String message = str;
				String cmd = str;
				// take first word
				int pos = str.indexOf(' ');	
				if (pos != -1) {
					cmd = str.substring(0, pos);
					str = str.substring(pos + 1);
				}
						
				//verify if we have banned words 
				int i;
				Boolean ban = false;
					for(i=0;i<bannedWords.length;i++){
						if(str.contains(bannedWords[i]))
							ban = true;
				}
					
				if(ban == true){
					//ban the user
					
					System.out.println("Ban user " + clientInfo.username);
					//tell the authorizationService to ban the user
					pwAuthorization.println("ban "+ clientInfo.username);
			    	pwAuthorization.flush();
			    	
			    	
			    	synchronized (servers) {
						
						Collection<ChatServer> sers = servers.values();
						
						Iterator<ChatServer> it = sers.iterator();
						
						while(it.hasNext()){
							
							ChatServer chatServer = it.next();
							
							int notIn=0;
							
							for(i=0;i<chatServer.clients.size();i++)
								if(chatServer.clients.get(i).username.equalsIgnoreCase(clientInfo.username)){
									try{
										chatServer.clients.get(i).pw.println("serverResponse: disconnected");
										chatServer.clients.get(i).pw.flush();
										chatServer.clients.get(i).pw.println("[SERVER]:You have been banned from server "+chatServer.name+" for a specific time");
										chatServer.clients.get(i).pw.flush();
								    	
									}catch(Exception e){
										System.out.println("Exceptie la trimitere pe socket " + e.getMessage());
										break;
									}
									
								chatServer.clients.remove(i);				
								System.out.println("User "+clientInfo.username+" removed from server " + chatServer.name);	
								}
						}
					}
			    	
				}
				else{
				//if user is not banned
					
				//check to ses if the user issued a command	
					if(cmd.compareToIgnoreCase("connect") == 0){
						
						String department = str;
						
						try{
						
							//get client's certificate information, specially the OU field
							SSLSession session = ((SSLSocket) s).getSession();
							X509Certificate[] cchain2 = session.getPeerCertificateChain();
							CertificateInfo certInfo = getCertificateInformation(((X509Certificate) cchain2[0]).getSubjectDN().getName());
					    
					    
					    	//see if the client is authorized to log to the server
					    	//--------------------------------------
					    	pwAuthorization.println("authorize "+ department +" "+certInfo.OU + " " + certInfo.CN);
					    	pwAuthorization.flush();
					    
					    
					    	String response = brAuthorization.readLine();
					    
					    	if(response.toLowerCase().compareTo("ok") != 0){
					    	
					    		String why = brAuthorization.readLine();
					    		System.out.println("Authorization Service refused connection for certificate released to"+ certInfo.CN +" because : " + why);
					  		
					    		pw.println("[SERVER]: Access denied :" + why);
					    		pw.flush();
					    	}
					    	//------------------------------------------
					    	else
					    	{ // connection ok
					    	  // attach to requested server queue	
					    		
					    		System.out.println("Access granted to user with certificate " + certInfo.CN + " to server " + department);
					    		//attach to server
					    		
					    		synchronized (servers) {
									
						    		ChatServer chatServer = servers.get(department.toLowerCase());
						    		if(chatServer == null ){
						    			System.out.println("Server " + department +" doesn't exist");
						    			pw.println("[SERVER]: Server " + department +" doesn't exist");
							    		pw.flush();
						    		}
						    		else
						    		{
						    			chatServer.clients.add(clientInfo);
						    			pw.println("serverResponse: connected " + department);
						    			pw.flush();
						    			
						    			pw.println("[SERVER "+department+"]: Access granted to server " + department);
						    			pw.flush();
						    		}
					    		}
					    		
					    	}
						}
						catch(Exception e){
							System.out.println("Exception in authorization process with authorization server service " + e.getMessage());
							
						}
						
					}
					else
						if(cmd.compareToIgnoreCase("disconnect") == 0){
						//disconnect user from department
							synchronized (servers) {
								
								Collection<ChatServer> sers = servers.values();
								
								Iterator<ChatServer> it = sers.iterator();
								
								while(it.hasNext()){
									
									ChatServer chatServer = it.next();
									for(i=0;i<chatServer.clients.size();i++)
										if(chatServer.clients.get(i).username.equalsIgnoreCase(clientInfo.username)){
											try{
												chatServer.clients.get(i).pw.println("serverResponse: disconnected");
												chatServer.clients.get(i).pw.flush();
												chatServer.clients.get(i).pw.println("[SERVER]:You have been disconnected from all servers");
												chatServer.clients.get(i).pw.flush();
										    	
											}catch(Exception e){
												System.out.println("Exceptie la trimitere pe socket " + e.getMessage());
												break;
											}
											
										chatServer.clients.remove(i);				
										System.out.println("User "+clientInfo.username+" removed from server " + chatServer.name);	
										}
								}
							}
							
						}
					else{
					
						//if user is not banned and has not issued a command
						//distribute his message to all connected users of that server except him
						
						Collection<ChatServer> sers = servers.values();
					
						Iterator<ChatServer> it = sers.iterator();
						
						while(it.hasNext()){
							
							ChatServer chatServer = it.next();
							
							if(chatServer.clients.contains(clientInfo)){
								//daca acesta este serverul din care face parte clientul
								//trimite mesagul si celorlalti clienti
								
								for(i=0;i<chatServer.clients.size();i++)
									if(!chatServer.clients.get(i).equals(clientInfo))
									try{
										chatServer.clients.get(i).pw.println("["+clientInfo.username+"][SERVER "+chatServer.name+"]:"+message);
										chatServer.clients.get(i).pw.flush();
									}catch(Exception e){
										System.out.println("Exceptie la trimitere pe socket " + e.getMessage());
										break;
									}
					
							}
								
						}
						
					}
				}
	
			}
			
			
			//synchronize access 
			System.out.println("Remove user clientinfo from servers");
			synchronized (servers) {
				int i;
				Collection<ChatServer> sers = servers.values();
				
				Iterator<ChatServer> it = sers.iterator();
				
				while(it.hasNext()){
					
					ChatServer chatServer = it.next();
					for(i=0;i<chatServer.clients.size();i++)
						if(chatServer.clients.get(i).username.equalsIgnoreCase(clientInfo.username)){
							chatServer.clients.remove(i);				
						System.out.println("User "+clientInfo.username+" removed from server " + chatServer.name);	
						}
				}
			}
			
			close();
			
		}
	}
	
	public static void main(String args[]) {
		if (args == null || args.length < 3) {
			System.out.println("Nu a fost furnizat ca argument portul server, portul serviciu autorizare si hostul serviciului de autorizare");
			return;
		}
		
		
		try {
			int port = Integer.parseInt(args[0]);
			int portService = Integer.parseInt(args[1]);
			String authHost = args[2];
			(new Thread(new Server(port,portService,authHost))).start();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
