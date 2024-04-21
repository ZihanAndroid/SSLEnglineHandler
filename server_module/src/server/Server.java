//server receives multiple files from a same client simultaneously and stored them in the folder
//"module-path/resources/receivedFiles/", the filename is the fileID defined by client
//This is a single-thread file receiver
package server;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.Iterator;
import java.util.Set;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;

import model.sslEngineUtil.ConnectionClosedException;
import model.sslEngineUtil.ConnectionErrorException;
import model.sslEngineUtil.SSLEngineGenerator;
import model.sslEngineUtil.SSLEngineHandler;

class SessionData{
	public File file;
	public FileChannel fileChannel;
	
	public SessionData(File file_, FileChannel fileChannel_) {
		file = file_;
		fileChannel = fileChannel_;
	}
	public void clearData() {
		if(fileChannel != null) {
			try {
				fileChannel.close();
			}catch(IOException e) {
				e.printStackTrace();
				System.out.println("Failed to close fileChannel in clearData() of SessionData");
			}
		}
		if(file != null) {
			file.delete();
		}
	}
	public void closeData(){
		try {
			fileChannel.close();
		}catch(IOException e) {
			e.printStackTrace();
			System.out.println("Failed to close fileChannel in clearData() of SessionData");
		}
	}
}

public class Server{
	private InetSocketAddress address = null;
	//here just one client communicate with one server, so just use one appBuffer to receive data
	private ByteBuffer appBuffer;
	//private ExecutorService threadPool = null;
	
	public Server(int port) {
		address = new InetSocketAddress(port);
		/*threadPool = Executors.newFixedThreadPool(3,new ThreadFactory(){
			public Thread newThread(Runnable r){
				Thread thread = Executors.defaultThreadFactory().newThread(r);
				thread.setDaemon(true);
				return thread;
			}
		});*/
	}
	
	public void start() {
		try(Selector selector = Selector.open(); ServerSocketChannel ssChannel = ServerSocketChannel.open()){
			SSLEngineGenerator sslEngineGenerator = new SSLEngineGenerator(new File(getClass().getResource("/resources/serverKeyStore/server.keyStore").toURI()),"passwd",new File(getClass().getResource("/resources/serverKeyStore/serverTrustedKeys.keyStore").toURI()),"passwd");
			ssChannel.bind(address);
			ssChannel.configureBlocking(false);
			ssChannel.register(selector,SelectionKey.OP_ACCEPT);
			System.out.println("The server has been started");
			while(true){
				try{
					if(selector.select() > 0){
						boolean isHandled = false;
						Set<SelectionKey> keys = selector.selectedKeys();
						Iterator<SelectionKey> iterator = keys.iterator();
						while(iterator.hasNext()){
							SelectionKey key = iterator.next();
							iterator.remove();
							
							if(key.isAcceptable()){
								isHandled = true;
								SSLEngineHandler handler = null;
								SocketChannel sChannel = null;
								try{
									sChannel = ssChannel.accept();
									if(sChannel != null){
										SSLEngine sslEngine = sslEngineGenerator.generateSSLEngine((InetSocketAddress)sChannel.getRemoteAddress());
										sslEngine.setUseClientMode(false);
										//sslEngine.setNeedClientAuth(true);
										sChannel.configureBlocking(false);
										handler = new SSLEngineHandler(sChannel,sslEngine);
										if(handler.doHandshake()){
										//you can set an attachment when register a SocketChannel, and use SelectionKey.attachment() to retrieve the attachment.
											System.out.println("Handshake success with " + sChannel.getRemoteAddress());
											sChannel.register(selector,SelectionKey.OP_READ | SelectionKey.OP_WRITE, handler);
											System.out.println("Session_id: " + sslEngine.getSession().getId());
											appBuffer = ByteBuffer.allocate(handler.getAppBufferSize());
										}else{
											throw new IOException("Failed to perform handshake with " + sChannel.getRemoteAddress());
										}
									}
								}catch(IOException e){
									if(!(e instanceof ConnectionClosedException)){
										e.printStackTrace();
									}
									if(handler != null){
										handler.serverHandleException(e);
									}else if(sChannel != null){
										try{
											sChannel.close();
										}catch(IOException ee){
											ee.printStackTrace();
										}
									}
								}
							}else if(key.isReadable()){
								isHandled = true;
								SSLEngineHandler sslEngineHandler = null;
								SSLSession session = null;
								SessionData sessionData = null;
								String fileID = null;
								//the Exception occurred when communicating with client should not cause the server exiting.
								try{
									sslEngineHandler = (SSLEngineHandler)key.attachment();
									session = sslEngineHandler.getSSLEngine().getSession();
									sslEngineHandler.receiveBuffer(appBuffer);	
									//System.out.printf("Received a packet, bytes %d\n",appBuffer.remaining());
									//fileID defined by client is used as filename
									while(appBuffer.hasRemaining()) {
										fileID = String.valueOf(appBuffer.getInt());
										//check if it is a new file
										if((sessionData = (SessionData)session.getValue(fileID)) == null) {
											System.out.println("A new file with fileID: " + fileID);
											//get the parent folder URL which exists, you can not get the URL for a file not existing, since it will return null
											URL url = getClass().getResource("/resources/receivedFiles/");
											int fileNameSize = appBuffer.getInt();
											byte[] fileNameBytes = new byte[fileNameSize];
											appBuffer.get(fileNameBytes);
											String fileNameString = new String(fileNameBytes,"utf-8");
											
											File parentFile = new File(url.toURI());
											File currentFile = new File(parentFile,fileNameString);
											System.out.println(currentFile.getAbsolutePath());
											//currentFile.createNewFile();
											
											FileChannel fileChannel = new FileOutputStream(currentFile).getChannel();
											//save both fileChannel and newFile to Session, if anything goes wrong with fileChannel, just access the newFile from Session and delete the newFile
											sessionData = new SessionData(currentFile, fileChannel);
											session.putValue(fileID, sessionData);
										}
										
										if(appBuffer.hasRemaining()) {
											int bytes = appBuffer.getInt();
											if(bytes != -1) {
												int prevLimit = appBuffer.limit();
												appBuffer.limit(appBuffer.position()+bytes);
												while(appBuffer.hasRemaining()) {
													sessionData.fileChannel.write(appBuffer);
												}
												appBuffer.limit(prevLimit);
											}else {
												//the end of file, the whole file has been received
												System.out.printf("file: %s, has been received\n",fileID);
												sessionData.closeData();
												session.removeValue(fileID);
												//send a reply to client indicating the file with fileID has been received
												ByteBuffer replyBuffer = ByteBuffer.allocate(4);
												replyBuffer.putInt(Integer.valueOf(fileID));
												replyBuffer.flip();
												sslEngineHandler.genWrappedBuffer(replyBuffer);
												System.out.printf("Reply to the client, the file %s has been received\n", fileID);
											}
										}
									}
								}catch(Exception e){
									if(!(e instanceof ConnectionClosedException)) e.printStackTrace();
									if(sessionData != null){
										sessionData.clearData();
									}
									if(fileID != null) {
										session.removeValue(fileID);
									}

									key.cancel();
									if(e instanceof ConnectionClosedException || e instanceof ConnectionErrorException){
										//clear Session for connection close
										//the files having not been received completely(SessionData.closeData() is not called) should be deleted
										for(String name : session.getValueNames()) {
											((SessionData)session.getValue(name)).clearData();
										}
									}
									sslEngineHandler.serverHandleException(e);
								}
							}
						}
						//the server has done nothing since previous selector.select()
						//Selector.select() will always return more than 0 if exiting keys
						//however the keys may not be ready for any operation, so just sleep to avoid busy waiting which greatly consuming CPU
						if(!isHandled) {
							Thread.sleep(10);
						}
					}
				}catch(IOException e){
					System.out.println("Server Failed when running");
					e.printStackTrace();
					throw e;
				}
			}
		}catch(Exception e){
			System.out.println("Failed to initialize the server");
			e.printStackTrace();
		}
	}
}