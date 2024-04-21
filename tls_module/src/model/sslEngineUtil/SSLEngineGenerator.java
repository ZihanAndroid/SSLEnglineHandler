package model.sslEngineUtil;

import java.security.KeyStore;
import java.io.File;
import java.security.SecureRandom;
import javax.net.ssl.SSLContext;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SNIServerName;
import java.util.ArrayList;
import java.net.InetSocketAddress;

public class SSLEngineGenerator{
	private SSLContext sslContext = null;
	private KeyStore keyStore = null;
	private KeyStore trustedKeyStore = null;
	
	private void initKeyStore(File file1, String passwd1, File file2, String passwd2) throws Exception{
		keyStore = new KeyStoreUtil(file1,passwd1,"AES",256).getKeyStore();
		trustedKeyStore = new KeyStoreUtil(file2,passwd2,"AES",256).getKeyStore();
	}
	private void initSSLContext(String passwd) throws Exception {
		KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX");
		kmf.init(keyStore,passwd.toCharArray());
		TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
		tmf.init(keyStore);
		
		sslContext = SSLContext.getInstance("TLSv1.3");
		sslContext.init(kmf.getKeyManagers(),tmf.getTrustManagers(),new SecureRandom());
	}
	/*private void setSNIServerName(SSLEngine engine, String... serverNames){
		SSLParameters param = engine.getSSLParameters();
		ArrayList<SNIServerName> servers = new ArrayList<>();
		for(String serverName : serverNames){
			servers.add(new SNIHostName(serverName));
		}
		param.setServerNames(servers);
		engine.setSSLParameters(param);
	}*/
	/*******************************************************public*******************************************************/
	//file1 => KeyStore for KeyManager		file2 =>	KeyStore for TrustManager
	public SSLEngineGenerator(File file1, String passwd1, File file2, String passwd2) throws Exception{
		initKeyStore(file1 ,passwd1, file2, passwd2);
		initSSLContext(passwd1);
	}
	//every connection has a SSLEngine with it
	public SSLEngine generateSSLEngine(String peerHost, int peerPort) throws Exception{
		SSLEngine engine = sslContext.createSSLEngine(peerHost, peerPort);
		engine.setUseClientMode(false);
		return engine;
	}
	public SSLEngine generateSSLEngine(InetSocketAddress address) throws Exception{
		SSLEngine engine = sslContext.createSSLEngine(address.getHostName(), address.getPort());
		engine.setUseClientMode(false);
		return engine;
	}
	//Not finished yet, SNI name
	/*public SSLEngine generateSSLEngine(String peerHost, int peerPort, String... serverNames) throws Exception{
		SSLEngine engine = generateSSLEngine(peerHost,peerPort);
		setSNIServerName(engine, serverNames);
		return engine;
	}
	public SSLEngine generateSSLEngine(InetSocketAddress address, String... serverNames) throws Exception{
		SSLEngine engine = generateSSLEngine(address);
		setSNIServerName(engine, serverNames);
		return engine;
	}*/
}