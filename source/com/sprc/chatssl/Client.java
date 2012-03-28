/**
	Tema 4 SPRC chatSSL
	@author Rizea Daniel
 */
 
package com.sprc.chatssl;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.util.Scanner;
import java.util.logging.Logger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;


public class Client {

	/** Logger used by this class */
	private static final transient Logger logger = Logger.getLogger("");

	private BufferedReader br;
	private PrintWriter pw;
	private SSLSocket s;
	public String serverConnected = null;
	
	public void createSSLConnection (String address, int port) throws Exception{

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
		s = (SSLSocket)ssf.createSocket();

		
		s.connect(new InetSocketAddress(address, port));

		pw = new PrintWriter(new OutputStreamWriter(s.getOutputStream()));
		br = new BufferedReader(new InputStreamReader(s.getInputStream()));

	} //createSSLConnection

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
	
	public void sendMessage (String command) {
		pw.println (command);
		pw.flush();
		//logger.info("Sent command "+command);
	} //sendCommand

	public String receiveResponseLine() throws Exception {
		return br.readLine() ;
	} //receiveResponseLine

	
	
	
	public static void main(String args[]) {
		if (args == null || args.length < 2) {
			System.out.println("Nu au fost furnizate adresa si portul serverului");
			return;
		}
		String host = args[0];
		int port = 0;
		try {
			port = Integer.parseInt(args[1]);
		} catch (Exception e) {
			e.printStackTrace();
			return;
		}
		
	
		Client c = new Client();
		
		try {
			
			c.createSSLConnection(host, port);
			//force certificate bi-auth on server and client
			c.sendMessage(" ");
			
			Runnable consoleRunnable = new ConsoleMessageListener(c);
			
			new Thread(consoleRunnable).start();
			
			Scanner scanner = new Scanner(System.in);
			
			
				System.out.println("Please use the connect command to connect to server");
				System.out.println("Ex: connect department (it, hr, management, acounting)");
			
			
			while(true){
				
				//System.out.println("mesaj:");
				//System.out.flush();
				// iau linia de comanda
				
				String str = scanner.nextLine();
				String cmd = str;
				String message = str;
				
				// iau primul cuvant
				int pos = str.indexOf(' ');
				if (pos != -1) {
					cmd = str.substring(0, pos);
					str = str.substring(pos + 1);
				} else {
					str = null;
				}
				// vad ce comanda am primit
				if (cmd.toLowerCase().compareTo("quit") == 0) {
					
					System.out.println("Good bye!");
					break;
				}
				
				
				
				c.sendMessage(message);
				
				
			}
			
			c.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

} // end of class Client

class ConsoleMessageListener implements Runnable{
    
	Client c = null;
	/** Logger used by this class */
	private static final transient Logger logger = Logger.getLogger("capV.example3.Client");
	
	public ConsoleMessageListener(Client c){
		this.c = c;
	}
	// This method is called when the thread runs
    public void run() {
    
    
    	while(true){
	
    		try{
    			String r = c.receiveResponseLine();
    			
    			String response = r;
    			
    			if(r.contains("serverResponse:")){
	    			
    				int pos = r.indexOf(' ');
	    			if(pos != -1){
	    				String cmd = r.substring(0, pos);
	    				r = r.substring(pos+1);
	    				//System.out.println(r);
	    				if(cmd.compareToIgnoreCase("serverResponse:") == 0){
	    					
	    					pos = r.indexOf(' '); 
	    					//System.out.println(r);
	    					if(pos != -1){
		    					cmd = r.substring(0, pos);
		        				r = r.substring(pos+1);
		        				if(cmd.compareToIgnoreCase("connected") == 0){
		    				
		        					//System.out.println(r);
		        					c.serverConnected = r;
		        					System.out.println("Connected with server");
		    				
		        				}else
		        					if(cmd.compareToIgnoreCase("disconnected") == 0){
		        						//System.out.println(r);
		        						c.serverConnected = null;
		        						System.out.println("Disconnected from server");
		        					}
	    					}
	    				}
	    			}
    			}else
    				
    				System.out.println("chat: " + response);
    			
    			if(r == null){
    				logger.info("Received null exiting: "+response);
    				break;
    			}
    			
    			//logger.info("Received: "+r);
    		}catch(Exception e){
    			System.out.println("Exit consoleThread " + e.getMessage());
    			break;
    		}
    	}
    
    }
}
