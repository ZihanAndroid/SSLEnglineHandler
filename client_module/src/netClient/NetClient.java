//client send files, server receive files
//test: client send 3 files at the same time and the server receives them simultaneously
package netClient;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.SSLEngine;

import javafx.application.Platform;
import javafx.beans.property.LongProperty;
import model.sslEngineUtil.SSLEngineGenerator;
import model.sslEngineUtil.SSLEngineHandler;
import presenter.Presenter;

public class NetClient {
	private SSLEngineHandler sslEngineHandler;
	private Presenter presenter;
	private String serverHostName;
	private int serverPort;
	private AtomicInteger fileID = new AtomicInteger(0);
	private Thread receivingThread = null;
	
	public NetClient(String serverHostName_, int serverPort_) throws Exception{
		serverHostName = serverHostName_;
		serverPort = serverPort_;
		try{
			sslEngineHandler = buildConnection();
		}catch(Exception e){
			e.printStackTrace();
			throw e;
		}
	}
	
	private static SocketChannel getSocketChannel() throws IOException{
		SocketChannel sChannel = SocketChannel.open();
		sChannel.configureBlocking(false);
		return sChannel;
	}
	//try connection for 3 times
	private SocketChannel tryConnect() throws IOException{
		int leftCount = 3;
		SocketChannel sChannel = null;
		while(leftCount > 0){
			leftCount -= 1;
			//the connection before has failed, and the old sChannel is closed, which can not be used to build a new connection, so create a new channel;
			sChannel = getSocketChannel();
			try{
				//return immediately for non-blocking channel
				sChannel.connect(new InetSocketAddress(serverHostName, serverPort));
				System.out.println((3-leftCount) + ": trying to connect to the server at " + sChannel.getRemoteAddress());				
				while(sChannel.isConnectionPending()){
					//return immediately for non-blocking channel, If the connection has failed, the finishConnect() call will throw an IOException. 
					if(sChannel.finishConnect()){
						leftCount = -1;
					}
				}
			}catch(IOException e){
				e.printStackTrace();
				System.out.print("Failed to connect to the server.");
				if(leftCount > 0){
					System.out.print(" Try again...");
				}
				System.out.println("\n");
			}
		}
		if(leftCount == 0){
			System.out.println("The program will exit");
			return null;
		}
		System.out.println("the connection is established");
		return sChannel;
	}
	
	//buildConnection will return a non-null SSLEngineHandler or throw an Exception
	private SSLEngineHandler buildConnection() throws IOException{
		SSLEngineHandler handler = null;
		SocketChannel sChannel = null;
		try {
			sChannel = tryConnect();
			if(sChannel != null) {
				SSLEngineGenerator sslEngineGen = new SSLEngineGenerator(new File(getClass().getResource("/resources/clientKeyStore/client.keyStore").toURI()),"passwd",new File(getClass().getResource("/resources/clientKeyStore/clientTrustedKeys.keyStore").toURI()),"passwd");
				SSLEngine sslEngine = sslEngineGen.generateSSLEngine((InetSocketAddress)sChannel.getRemoteAddress());
				sslEngine.setUseClientMode(true);
				handler = new SSLEngineHandler(sChannel,sslEngine);
				if(!handler.doHandshake()){
					throw new IOException("handshake failure");
				}
				System.out.println("Handshake success with " + sChannel.getRemoteAddress());
			}
		}catch(Exception e) {
			//the SSLEngineGenerator may throw some other Exception other than IOExcetion
			e.printStackTrace();
			if(handler != null){
				handler.clientHandleException(e);
			}else if(sChannel != null){
				try{
					sChannel.close();
				}catch(IOException ee){
					ee.printStackTrace();
				}
			}
		}
		if(handler == null) {
			throw new IOException("Failed to build connection");
		}
		
		final SocketChannel socketChannel = sChannel;
		receivingThread = new Thread(()->{
			ByteBuffer revBuffer = ByteBuffer.allocate(sslEngineHandler.getAppBufferSize());
			try(Selector selector = Selector.open()){
				socketChannel.register(selector, SelectionKey.OP_READ);
				boolean isExit = false;
				while(!isExit) {
					if(selector.select() > 0) {
						Set<SelectionKey> selectedKeys = selector.selectedKeys();
						Iterator<SelectionKey> iterator = selectedKeys.iterator();
						while(iterator.hasNext()) {
							//only one key here
							iterator.next();
							iterator.remove();
							sslEngineHandler.receiveBuffer(revBuffer);
							//you may receive handshake(control) data and the revBuffer is empty
							while(revBuffer.hasRemaining()) {
								int fileID = revBuffer.getInt();
								System.out.printf("Receiving message from server, file %d has been received\n", fileID);
								Platform.runLater(()->presenter.fileReceived(fileID));
							}
						}
					}else {
						try {
							Thread.sleep(1000);
						}catch(InterruptedException e) {
							isExit = true;
						}
					}
				}
			}catch(IOException e) {
				e.printStackTrace();
				try {
					sslEngineHandler.clientHandleException(e);
				}catch(IOException ee) {
					Platform.runLater(()->presenter.exitWithConnectionError());
				}
			}
		});
		receivingThread.start();
		
		return handler;
	}
	
	/***********************************public methods***********************************/
	//for all the public methods, if IOException occurs when calling methods of SSLEngineHandler, you should just
	//close the connection here, and let Presenter decides whether to rebuild the connection
	//finished LongProperty is provided by Presenter, used to record the sent data
	//sendFile either success or if the connection is closed, an IOException will be thrown to indicate the netClient
	//to rebuilt a connection or just Platform.exit();
	public int sendFile(String fileName, FileChannel filechannel, LongProperty finished) throws IOException{
		if(fileName.length() > 100) {
			//avoid infinite length of fileName
			throw new IOException("The file name is too long, should be less than 100 characters");
		}
		long[] sentBytes = {0L};
		int fileId = fileID.getAndAdd(1);
		try {
			ByteBuffer nameBuffer = ByteBuffer.wrap(fileName.getBytes("utf-8"));
			ByteBuffer nameSizeBuffer = ByteBuffer.allocate(4);
			nameSizeBuffer.putInt(nameBuffer.remaining());
			nameSizeBuffer.flip();
			//fileID
			ByteBuffer headerBuffer = ByteBuffer.allocate(4);
			headerBuffer.putInt(fileId);
			headerBuffer.flip();
			//make the appBufferSize smaller than netBufferSize(approximately 16000) in SSLEngineHandler to avoid BufferOverFlow
			int appBufferSize = sslEngineHandler.getAppBufferSize()-1000;
			ByteBuffer dataBuffer = ByteBuffer.allocate(appBufferSize);
			ByteBuffer dataSizeBuffer = ByteBuffer.allocate(4);
			int count = 0;
			int readBytes = 0;
			while((readBytes = filechannel.read(dataBuffer)) != -1) {
				//System.out.println("Bytes read from file: " + readBytes);
				if(readBytes == 0) {
					//read nothing from FileChannel, since the empty dataBuffer means last packet for server, we just skip it
					dataBuffer.clear();
					continue;
				}
				dataBuffer.flip();
				sentBytes[0] += dataBuffer.limit();
				dataSizeBuffer.putInt(dataBuffer.limit());
				dataSizeBuffer.flip();
				/*System.out.println(headerBuffer.remaining());
				System.out.println(dataBuffer.remaining());*/
				//send the whole dataBuffer to server, the valid data is specified by dataSizeBuffer
				//dataBuffer.clear();
				if(count == 0) {
					sslEngineHandler.genWrappedBuffer(new ByteBuffer[] {headerBuffer,nameSizeBuffer,nameBuffer,dataSizeBuffer,dataBuffer});
				}else {
					sslEngineHandler.genWrappedBuffer(new ByteBuffer[] {headerBuffer,dataSizeBuffer,dataBuffer});
				}
				dataBuffer.clear();
				headerBuffer.clear();
				dataSizeBuffer.clear();
				++count;
				if(count % 100 == 0) {
					Platform.runLater(()->finished.set(sentBytes[0]));
				}
			}
			dataSizeBuffer.putInt(-1);
			dataSizeBuffer.flip();
			//a special packet indicating the end of the file with dataSizeBuffer value -1
			sslEngineHandler.genWrappedBuffer(new ByteBuffer[] {headerBuffer,dataSizeBuffer});
			System.out.printf("The last packet of file %d has been sent to SSLEngineHandler\n", fileId);
			//send the last packet with the "original header + empty data" to indicate the end of file to the server
			Platform.runLater(()->finished.set(sentBytes[0]));
		}catch(IOException | InterruptedException e) {
			e.printStackTrace();
			sslEngineHandler.clientHandleException(e);
		}
		return fileId;
	}
	
	public void setPresenter(Presenter presenter_) {
		presenter = presenter_;
	}
	
	public void exit() {
		if(receivingThread != null) {
			receivingThread.interrupt();
		}
		try {
			sslEngineHandler.closeConnection();
		}catch(IOException e) {
			//this version do not throw new Exception
			sslEngineHandler.serverHandleException(e);
		}
	}
}