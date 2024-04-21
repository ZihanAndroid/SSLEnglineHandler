//client version, for server after handshake, the threadPool here should be shutdown and the server should create a new thread to sendWrappedBuffer() when neccessary(eg: sending a big file) instead of keeping an extra alive thread in threadPool for every client connection
//only one thread is responsible for writing(calling sendWrappedBuffer()), so there is no need to use Selector for client non-blocking SocketChannel
package model.sslEngineUtil;

import static javax.net.ssl.SSLEngineResult.HandshakeStatus.FINISHED;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.Semaphore;
import java.util.concurrent.ThreadFactory;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;

//Socket channels are safe to use by multiple concurrent threads.
//there are multiple threads to send data to data, but only one thread is used to receive data from client, for client, it is the same(multiple send, one receive)
//every time you call sslEngineHandler.receiveBuffer() or sslEngineHandler.sendBuffer(), you will take up a netBufferIn or a netBufferOut in SSLEngineHandler
public class SSLEngineHandler{
	private SocketChannel sChannel = null;
	private SSLEngine sslEngine = null;
	private ExecutorService threadPool = null;
	//only one netBufferIn, because of BUFFER_UNDERFLOW in receiveBuffer which causes the data in netBufferIn may not be fetch completely and the concurrent constrains of SSLEngine.unwrap()
	private ByteBuffer netBufferIn = null;
	//but there may be multiple netBufferOuts, when you send a file by SSLEngine, to speed it up, you may use one thread genWrappedBuffer and the other thread sendWrappedBuffer
	private ByteBuffer netBufferOut = null;
	private ByteBuffer hsAppDataBufferIn = null;
	private ByteBuffer hsAppDataBufferOut = null;
	private ByteBuffer[] netBufferOuts;
	//store the indexes of netBufferOuts which are done wrap() by genWrappedBuffer() method
	//LinkedBlockingQueue has a lock for take() and put() respctively, in fact, here there is only one thread calling take()(sending thread) and one thread calling put()(the thread that is synchronized by wrapLock) at the same time
	private LinkedBlockingQueue<Integer> netBufferOutIndexes;
	//ConcurrentLinkedQueue: no lock in it
	private ConcurrentLinkedQueue<Integer> avaliableIndexes;
	private Object wrapLock = new Object();
	private Semaphore semaphoreRev = new Semaphore(1);
	private boolean[] sendingThreadClosed = {false};
	private boolean isSometingWrongInReceiving = false;
	
	//channel is a SocketChannel or AsynchronousSocketChannel which has connected to the peer
	public SSLEngineHandler(SocketChannel channel, SSLEngine engine, int threadNum){
		sChannel = channel;
		sslEngine = engine;
		//the value of netBufferOutNum needs to be tuned
		int netBufferOutNum = threadNum*2;
		avaliableIndexes = new ConcurrentLinkedQueue<Integer>();
		netBufferOutIndexes = new LinkedBlockingQueue<Integer>();
		int netBufferSize = sslEngine.getSession().getPacketBufferSize();
		netBufferOuts = new ByteBuffer[netBufferOutNum];
		for(int i = 0;i < netBufferOutNum;++i){
			//throw unchecked Exception: IllegalStateException, which should never happen unless the logic of program is wrong
			avaliableIndexes.offer(i);
		}
		netBufferIn = ByteBuffer.allocate(netBufferSize);
		netBufferOut = ByteBuffer.allocate(netBufferSize);
		//handshake data will not show up in the hsAppDataBufferIn & hsAppDataBufferOut, but will show up in the netBufferOut & netBufferIn
		hsAppDataBufferIn = ByteBuffer.allocate(1);
		hsAppDataBufferOut = ByteBuffer.allocate(1);
		threadPool = Executors.newFixedThreadPool(1,new ThreadFactory(){
			public Thread newThread(Runnable r){
				Thread thread = Executors.defaultThreadFactory().newThread(r);
				thread.setDaemon(true);
				return thread;
			}
		});
	}
	public SSLEngineHandler(SocketChannel channel, SSLEngine engine){
		this(channel,engine,8);
	}
	//no matter in client or server, all the operation is done in threadPool(not the one defined in SSLEngineHandler), the fixed threadPool will execute max "threadNum" threads, and each thread will only take up one netBufferOut
	//(not true, will take up multiple buffers if send bigBuffer or a file)
	private int getBufferIndex() throws IOException{
		Integer index = null;
		while(index == null){
			index = avaliableIndexes.poll();
			if(index == null){
				Thread.onSpinWait();
			}else if(netBufferOuts[index] == null){
				//lazy initialization
				netBufferOuts[index] = ByteBuffer.allocate(sslEngine.getSession().getPacketBufferSize());
			}
		}			
		return index;
	} 
	private ByteBuffer enlargeBuffer(ByteBuffer oldBuffer, int properSize){
		ByteBuffer buffer = ByteBuffer.allocate(properSize);
		buffer.put(oldBuffer);
		return buffer;
	}
	//will throw an Exception, either ConnectionClosedException if everything is ok, or IOException
	//Exception occurs when read or write to channel, you call handleChannelBreak(), and handleChannelBreak will throw an Exception eventually to exit the current connection.
	private void handleChannelBreak() throws IOException{
		try{
			sslEngine.closeInbound();
		}catch(IOException e){
			e.printStackTrace();
			throw new ConnectionErrorException("The peer closed connection unexpectly:\n");
		}
		if(!sslEngine.isOutboundDone()){
			closeConnection();
		}else{
			//the connection closed with manner.
			throw new ConnectionClosedException();
		}
	}
	/*private boolean hasRemaining(ByteBuffer[] bufferIns){
		boolean res = false;
		for(int i = 0; i < bufferIns.length;++i){
			if(bufferIns[i].hasRemaining()){
				res = true;
				break;
			}
		}
		return res;
	}*/
	//close the connection actively(call SSLEngine.closeOutbound())	=>	after wrap(), when isOutboundDone() return true	=>	SSLEngineResult.Status is CLOSED
	//close the connection passively(the other side call SSLEngine.closeOutbound(),at last will cause the isInboundDone() return true for the current side)
	//	=>	after unwrap(), when isInboundDone() return true	=>	SSLEngineResult.Status is CLOSED
	//will throw ConnectionClosedException if doHandshake handle the connection close properly.
	private boolean doHandshake(boolean isHandshake) throws IOException{
		if(isHandshake){
			sslEngine.beginHandshake();
		}
		SSLEngineResult.HandshakeStatus status = sslEngine.getHandshakeStatus();
		int count = 0;
		int properSize = 0;
		SSLEngineResult res = null;
		while(status != SSLEngineResult.HandshakeStatus.FINISHED && status != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING){
			//System.out.println(status);
			switch(status){
				//handshake data stored in netBufferIn, so be careful when dealing with it.
				//Only when handshaking will enter the NEED_UNWRAP HandShakeStatus
				case NEED_UNWRAP:
					hsAppDataBufferIn.clear();
					try{
						count = sChannel.read(netBufferIn);
					}catch(IOException e){
						return false;
					}
					if(count < 0){
						handleChannelBreak();
						return false;
					}
					netBufferIn.flip();
					res = sslEngine.unwrap(netBufferIn, hsAppDataBufferIn);
					status = res.getHandshakeStatus();
					switch(res.getStatus()){
						case OK:
							//prepare for another sChannel.read(netBufferIn);
							netBufferIn.compact();
							break;
						//when you have received a close_notify from netBufferIn(calling sslEngine.unwrap(netBufferIn, hsAppDataBufferIn)), you will get to CLOSEED in NEED_UNWRAP
						//after you have received a close_notify, the isInboundClosed() of SSLEngine is true, then you call closeInbound() will not throw SSLException.
						case CLOSED:
							System.out.println("the other peer says close the connection when handshaking.");
							if(!sslEngine.isOutboundDone()){
								closeConnection();
							}
							return false;
						case BUFFER_OVERFLOW:
							properSize = sslEngine.getSession().getApplicationBufferSize();
							if(hsAppDataBufferIn.capacity() < properSize){
								hsAppDataBufferIn = enlargeBuffer(hsAppDataBufferIn,properSize);
								netBufferIn.compact();
							}else{
								throw new IOException("Should not be here in doHandshake() NEED_UNWRAP BUFFER_OVERFLOW when hsAppDataBufferIn capacity is large enough");
							}
							break;
						case BUFFER_UNDERFLOW:
							properSize = sslEngine.getSession().getPacketBufferSize();
							if(netBufferIn.capacity() < properSize){
								netBufferIn = enlargeBuffer(netBufferIn,properSize);
							}else{
								netBufferIn.compact();
							}
							break;
					}
					break;
				//when handshaking or after calling SSLEngine.closeOutbound() will enter into NEED_WRAP.
				case NEED_WRAP:
					netBufferOut.clear();
					//handshake data will be gererated to netBufferOut, you must send out all the data in netBufferOut 	
					res = sslEngine.wrap(hsAppDataBufferOut,netBufferOut);
					netBufferOut.flip();
					status = res.getHandshakeStatus();
					switch(res.getStatus()){
						case OK:
							while(netBufferOut.hasRemaining()){
								try{
									sChannel.write(netBufferOut);	
								}catch(IOException e){
									handleChannelBreak();
								}
							}
							break;
						//when you call closeOutbound() and SSLEngine.wrap(), you will get to CLOSED in NEED_WRAP
						case CLOSED:
							//when get to CLOSED, it means after sslEngine.wrap(hsAppDataBufferOut,netBufferOut); the close_notify has generated to netBufferOut
							//but the close_notify has not been sent yet, do not forget to sent it out by sChannel.write(netBufferOut);
							//However, there are 2 situation:
							//1.	After you call closeConnection() to close the connection actively while the other side does not, you get here, at this time, SocketChannel is not closed, there is no problem when sChannel.write(netBufferOut);	
							//2. the other side has already closed the connection and SocketChannel, you call closeConnection() passively, now, if you call sChannel.write(netBufferOut);	 IOException will be thrown since the SocketChannel has been closed;
							while(netBufferOut.hasRemaining()){
								try{
									sChannel.write(netBufferOut);	
								}catch(IOException e){
									//e.printStackTrace();
									System.out.println("The other peer has closed SocketChannel and does not accept close_notify.");
									handleChannelBreak();
								}
							}
							System.out.println("The close_notify has been sent to the peer.");
							throw new ConnectionClosedException();
						case BUFFER_OVERFLOW:
							properSize = sslEngine.getSession().getPacketBufferSize();
							if(netBufferOut.capacity() < properSize){
								netBufferOut = enlargeBuffer(netBufferOut,properSize);
							}else{
								throw new IOException("Should not occur BUFFER_OVERFLOW in NEED_WRAP when netBufferOut capacity is large enough");
							}
							break;
						case BUFFER_UNDERFLOW:
							throw new IOException("should never occur BUFFER_UNDERFLOW in SSLEngine.wrap()");
					}
					break;
				case NEED_TASK :
					Runnable task = null;
					while((task = sslEngine.getDelegatedTask()) != null){
						threadPool.submit(task);
					}
					status = sslEngine.getHandshakeStatus();
					break; 
			}
		}
		if(status == FINISHED){
			//not finished yet
			//client will check whether the server hostname is the same as the name verified in certificate
			//but server does not do so
			/*if(sslEngine.getUseClientMode() && isHandshake){
				// Note: InetSocketAddress.getHostName()	This method may trigger a name service reverse lookup if the address was created with a literal IP address.
				String serverHost = ((InetSocketAddress)sChannel.getRemoteAddress()).getHostName();
				//change it: www.learningandtesting.xyz => serverHost
				if(hostNameVerifier.verify("www.learningandtesting.xyz", sslEngine.getSession())){
					return true;
				}else{
					throw new IOException("The server name does not match the certificate.\nServer Host: " + serverHost);
				}
			}else{
				return true;
			}*/
			System.out.println("hsAppDataBufferIn: " + hsAppDataBufferIn.capacity());
			System.out.println("hsAppDataBufferOut: " + hsAppDataBufferOut.capacity());
			System.out.println("netBufferIn: " + netBufferIn.capacity());
			System.out.println("netBufferOut: " + netBufferOut.capacity());
			
			//SSLEngine sending thread
			threadPool.submit(()->{
				try{
					sendWrappedBuffer();
				}catch(InterruptedException e){
					//the thread will exit by Thread.interrupt()
				}catch(IOException e){
					System.out.println("IOException occurs when sending data to the peer in SSLEngine sending thread, the connection will be closed");
					serverHandleException(e);
					//at this time the client now nothing at the sending thread in SSLEngineHandler has been closed, only after the genWrappedBuffer() is called will the client knows it
					sendingThreadClosed[0] = true;
				}
			});
			
			return true;
		}
		return false;
	}
	private void sendWrappedBuffer() throws IOException,InterruptedException{
		while(true){
			if(Thread.currentThread().isInterrupted()){
				throw new InterruptedException();
			}
			//will be blocked if netBufferOutIndexes is empty
			Integer index = netBufferOutIndexes.take();
			ByteBuffer bBuffer = netBufferOuts[index];
			//using synchronized to avoid partial write in concurrent env. Since it is a non-blocking SocketChannel
			while(bBuffer.hasRemaining()){
				try{
					sChannel.write(bBuffer);
				}catch(IOException e){
					handleChannelBreak();
				}
			}
			avaliableIndexes.offer(index);
		}
	}
	/***********************************************************public method***********************************************************/
	//when you call closeConnection() it will throw an Exception no matter which situation(ConnectionClosedException or other IOException)
	//which is convenient for exiting the program using Exception.
	//You may call closeConnection multiple times in some cases, and the latter calls will hava no effect
	public void closeConnection() throws IOException{
		//turn the HandShakeStatus from NOT_HANDSHAKING to NEED_WRAP, use doHandshake(false) to handle NEED_WRAP to send close_notify
		sslEngine.closeOutbound();
		try{
			//send close_notify message
			doHandshake(false);
			if(sslEngine.isOutboundDone()){
				throw new ConnectionClosedException();
			}else{
				throw new ConnectionErrorException("Failed to close connection normally");
			}
		}catch(IOException e){
			throw e;
		}finally{
			//if you do not shutdown the threadPool in closeConnection, there will be non-daemon thread existing, which stop the program from exitting. 
			sChannel.close();
			//according to java doc. the typical implementations of ExecutorService will cancel the thread via Thread.interrupt()
			threadPool.shutdownNow();
		}
	}
	public boolean doHandshake() throws IOException{
		return doHandshake(true);
	}
	//the user only need to call genWrappedBuffer and the generated wrapped buffer will be sent by sendingThread in threadPool of SSLEngineHandler
	//genWrappedBuffer() is a blocking method, it is used when you need to send big file by TLS, you may use one thread responsible for genWrappedBuffer and the other thread responsible for sendWrappedBuffer()
	public void genWrappedBuffer(ByteBuffer[] bufferIns) throws IOException,InterruptedException{
		if(sendingThreadClosed[0]){
			throw new ConnectionErrorException("The sending thread in SSLEngine has been closed, ConnectionErrorException");
		}
		//getBufferIndex() will be blocked if the index is not avaliable immediately
		int index = getBufferIndex();
		ByteBuffer bufferOut = netBufferOuts[index];
		bufferOut.clear();
		int properSize = 0;
		//See java doc SSLEngine: The SSL/TLS/DTLS protocols employ ordered packets. Applications must take care to ensure that generated packets are delivered in sequence. 
		//As a corollary, two threads must not attempt to call the same method (either wrap() or unwrap()) concurrently, because there is no way to guarantee the eventual packet ordering.
		//Therefore using "synchronized" modifier here
		synchronized(wrapLock){
			//while(hasRemaining(bufferIns)){
			while(bufferIns[bufferIns.length-1].hasRemaining()){
				SSLEngineResult res = null;
				res = sslEngine.wrap(bufferIns, bufferOut);
				switch(res.getStatus()){
					case BUFFER_OVERFLOW:
						properSize = sslEngine.getSession().getPacketBufferSize();
						if(bufferOut.capacity() < properSize){
							bufferOut.flip();
							netBufferOuts[index] = enlargeBuffer(bufferOut,properSize);
							bufferOut = netBufferOuts[index];
						}else{
							throw new IOException("Should not occur BUFFER_OVERFLOW in sendBuffer() when netBufferOut capacity is large enough");
						}
						break;
					case BUFFER_UNDERFLOW:
						throw new IOException("Should never occur BUFFER_UNDERFLOW in SSLEngine.wrap(...) method");
					case OK:
						break;
					case CLOSED:
						//CLOSED state for wrap() should occurred in handshake, not in sendBuffer(when you are still calling sendBuffer, it is impossible that you have called closeOutbound() before)
						throw new IOException("Should not be CLOSED status for SSLEngine in sendBuffer()");
				}
			}
			bufferOut.flip();
			netBufferOutIndexes.put(index);
		}
	}
	public void genWrappedBuffer(ByteBuffer bufferIn) throws IOException,InterruptedException{
		genWrappedBuffer(new ByteBuffer[]{bufferIn});
	}
	//return true if there is data received in dataBuffer or false if no valid data received or another thread is calling receiveBuffer(), so you should not touch dataBuffer in this case
	//you should guarantee the dataBuffer is large enough to hold the bytes generated by unwrap() method
	//every time you call receiveBuffer, you may get multiple packet in dataBuffer, so using a while loop to handle all the data in dataBuffer so that you will not miss something
	public boolean receiveBuffer(ByteBuffer dataBuffer) throws IOException{
		//dataBuffer may be empty(dataBuffer.hasRemaining() is false), so you should check it before using dataBuffer after calling receiveBuffer(dataBuffer)
		if(!semaphoreRev.tryAcquire()){
			//some other thread is dealing with the data receiving for this client, so just skip it since we use only one thread for receiving and unwrap() data at some time
			//reset dataBuffer, when you call dataBuffer.hasRemaining() it will return false
			dataBuffer.position(dataBuffer.limit());
			return false;
		}
		dataBuffer.clear();
		int count = 0;
		int properSize = 0;
		//since SocketChannel.read() may read incomplete data into the end of the data bytes in netBufferIn, use isSometingWrongInReceiving to handle it, if the SSLException or BufferOverflow is caused by 
		//incomplete data, the isSometingWrongInReceiving will allow receiving the data one more time. However if the later one still fails, then the method will throw IOException to indicate the failure
		try{
			count = sChannel.read(netBufferIn);
		}catch(IOException e){
			handleChannelBreak();
		}
		if (count < 0){
			handleChannelBreak();
		}else{
			netBufferIn.flip();
			//in handshake, there is the instruction by NEED_WRAP and NEED_UNWRAP, so you do not need to use a while loop to consume all the data in netBufferIn
			//while here, there is no such instruction, so consuming all the possible data in netBufferIn
			//required by SSLEngineImpl
			//while(netBufferIn.remaining() > 15){
			boolean isQuit_ = false;
			while(!isQuit_){
				//call unwrap() one time will only decode one message encoded by wrap() in the other side. 
				SSLEngineResult res = null;
				try{
					res = sslEngine.unwrap(netBufferIn, dataBuffer);
				}catch(SSLException e){
					if(isSometingWrongInReceiving) throw e;	
					else{
						//System.out.println(e.getMessage());
						isSometingWrongInReceiving = true;
						break;
					}
				}
				switch(res.getStatus()){
					//after unwrap(), if you received a close_notify from the other side, the status of SSLEngine will be CLOSED, which is an alert that you should closeConnection() 
					case CLOSED:
						System.out.println("the other side: " + sChannel + "\nwants to close the connection\n");
						//System.out.println("isInboundDone(): " + sslEngine.isInboundDone()); //is true
						closeConnection();
						throw new ConnectionClosedException();
					case OK:
						if(!netBufferIn.hasRemaining()) isQuit_ = true;
						isSometingWrongInReceiving = false;
						break;
					case BUFFER_OVERFLOW:
						//System.out.println("BUFFER_OVERFLOW");
						/*properSize = sslEngine.getSession().getApplicationBufferSize();
						if(dataBuffer.capacity() < properSize){
							dataBuffer.flip();
							dataBuffer = enlargeBuffer(dataBuffer, properSize);
						}else{
							throw new IOException("Should not occur BUFFER_OVERFLOW in receiveBuffer() when dataBuffer capacity is large enough");
						}*/
						if(isSometingWrongInReceiving){
							throw new IOException("should not occur BufferOverflow when the appBuffer is assumed large enough in receiveBuffer");
						}else{
							isSometingWrongInReceiving = true;
							isQuit_ = true;
						}
						break;
					// last unwrap() will generate nothing if BUFFER_UNDERFLOW occurs
					case BUFFER_UNDERFLOW:
						//System.out.println("BUFFER_UNDERFLOW");
						isQuit_ = true;
						properSize = sslEngine.getSession().getPacketBufferSize();
						if(netBufferIn.capacity() < properSize){
							System.out.println("enlargeBuffer");
							netBufferIn = enlargeBuffer(netBufferIn, properSize);
							//cancel the effect of compact by enlargeBuffer() method
							netBufferIn.flip();
						}
						isSometingWrongInReceiving = false;
						break;
				}
			}
			//you must keep the data in netBufferIn which may not be comsumed because of BUFFER_UNDERFLOW so that you will not lose or mess any SSLEngine data
			netBufferIn.compact();
			//BUFFER_UNDERFLOW occurs and the there will be more data. for multiple thread which netBufferIn is different in every thread, you must wait for more data coming so that you will not lose any data
		}
		dataBuffer.flip();
		semaphoreRev.release();
		return dataBuffer.hasRemaining();
	}
	public SocketChannel getSocketChannel(){
		return sChannel;
	}
	public SSLEngine getSSLEngine(){
		return sslEngine;
	}
	public int getAppBufferSize(){
		return sslEngine.getSession().getApplicationBufferSize();
	}		
	//figure out the situation of Exception and close connection if neccessary.
	//if you call handleException and received an IOException, it means the current connection is break and you should try to reconnect to the server or call Platform.exit()
	public void clientHandleException(Exception e) throws IOException{
		if(e instanceof ConnectionErrorException){
			throw (ConnectionErrorException)e;
		}
		if(!(e instanceof ConnectionClosedException)){
			System.out.println("Exception occurs during TLS transmission with peer:\n" + getSocketChannel());
			try{
				closeConnection();
			}catch(IOException ee){
				if(!(ee instanceof ConnectionClosedException)){
					System.out.println("IOException occurs when closing the connection:\n");
					ee.printStackTrace();
				}else{
					System.out.println("Connection closed.");
					throw ee;
				}
			}
		}else{
			System.out.println("Connection closed.");
			throw (ConnectionClosedException)e;
		}
	}
	//this version of handleException do not throw IOException
	public void serverHandleException(Exception e){
		if(!(e instanceof ConnectionClosedException)){
			System.out.println("Exception occurs during TLS transmission with peer:\n" + getSocketChannel());
			try{
				closeConnection();
			}catch(IOException ee){
				if(!(ee instanceof ConnectionClosedException)){
					System.out.println("IOException occurs when closing the connection:\n");
					ee.printStackTrace();
				}else{
					System.out.println("Connection closed.");
				}
			}
		}else{
			System.out.println("Connection closed.");
		}
	}
}