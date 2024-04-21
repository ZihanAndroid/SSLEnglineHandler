package presenter;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.time.LocalTime;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;

import fxml_controller.ErrorPanelController;
import fxml_controller.PanelController;
import javafx.application.Platform;
import javafx.beans.property.LongProperty;
import javafx.beans.property.SimpleLongProperty;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.FileChooser.ExtensionFilter;
import javafx.stage.Modality;
import javafx.stage.Stage;
import netClient.NetClient;

public class Presenter {
	private PanelController[] controllers;
	private NetClient netClient;
	private FileChooser fileChooser = new FileChooser();
	private Stage stage;
	private File[] files = new File[3];
	private VBox errorPane;
	private ErrorPanelController errorController;
	//controller i send file with fileId controllerFileIndexes[i]
	private int[] controllerFileIndexes;
	private ExecutorService threadPool = null;
	
	private String countTime(int seconds) {
		int m = seconds / 60;
		int s = seconds % 60;
		return String.format("%02d:%02d",m,s);
	}
	
	private void setHandler(PanelController controller, int index) {
		controller.fileButton.setOnAction(event->{
			files[index] = fileChooser.showOpenDialog(stage);
			if(files[index] == null) {
				controller.pathLabel.setText("No file is chosen");
			}else {
				controller.pathLabel.setText(files[index].getAbsolutePath());
				fileChooser.setInitialDirectory(files[index].getParentFile());
			}
		});
		controller.sendButton.setOnAction(event->{
			controller.resLabel.setText("");
			if(files[index] != null) {
				FileChannel fileChannel = null;
				try{
					fileChannel = new FileInputStream(files[index]).getChannel();
					LongProperty finished = new SimpleLongProperty(0L);
					long totalSize = fileChannel.size();
				
					final LocalTime[] previousTime = {LocalTime.now()};
					finished.addListener((longProperty,oldValue,newValue)->{
						LocalTime nowTime = LocalTime.now();
						long milliSeconds = previousTime[0].until(nowTime, ChronoUnit.MILLIS)+1;
						//previousTime[0] = nowTime;
						long sent = (newValue.longValue())*1000 / milliSeconds / 1024;
						if(sent > 1024) {
							sent = sent/1024;
							controller.speedLabel.setText(String.format("%d MB/s", sent));
						}else {
							controller.speedLabel.setText(String.format("%d KB/s", sent));
						}
						controller.leftLabel.setText(String.format("%dMB/%dMB", newValue.longValue()/1024/1024, totalSize/1024/1024));
						double persent = newValue.longValue()/(double)totalSize;
						controller.progressBar.setProgress(persent);
					});
					
					final int[] seconds = {0};
					Thread tickingThread = new Thread(()->{
						try {
							while(true) {
								Thread.sleep(1000);
								Platform.runLater(()->controller.timeLabel.setText(countTime(++seconds[0])));
							}
						}catch(InterruptedException e) {}
					});
					
					//send file
					FileChannel fileChannel_ = fileChannel;
					threadPool.submit(()->{
						tickingThread.start();
						try {
							controllerFileIndexes[index] = netClient.sendFile(files[index].getName(),fileChannel_,finished);
						}catch(IOException e) {
							e.printStackTrace();
							Platform.runLater(()->exitWithConnectionError());
						}finally {
							try {
								fileChannel_.close();
							}catch(IOException ee) {
								ee.printStackTrace();
							}
							tickingThread.interrupt();
						}
					});
				}catch(IOException e) {
					e.printStackTrace();
					controller.resLabel.setText("Failed to send file");
					if(fileChannel != null) {
						try {
							fileChannel.close();
						}catch(IOException ee) {
							ee.printStackTrace();
						}
					}
				}
			}else {
				controller.resLabel.setText("You have not chosen a file to be sent");
			}
		});
	}
	
	public Presenter(Stage stage_, PanelController[] controllers_, NetClient netClient_) {
		stage = stage_;
		controllers = controllers_;
		netClient = netClient_;
		netClient.setPresenter(this);
		FileChooser fileChooser = new FileChooser();
		fileChooser.setTitle("Send File");
		fileChooser.getExtensionFilters().addAll(
			new ExtensionFilter("Text Files", "*.txt"),
		    new ExtensionFilter("Image Files", "*.png", "*.jpg", "*.gif"),
		    new ExtensionFilter("Audio Files", "*.wav", "*.mp3", "*.aac"),
		    new ExtensionFilter("All Files", "*.*"));
		for(int i = 0; i < controllers.length;++i) {
			setHandler(controllers[i],i);
		}
		
		FXMLLoader errorPaneLoader = new FXMLLoader(getClass().getResource("/resources/fxml/errorPanel.fxml"));
		try{
			errorPane = errorPaneLoader.<VBox>load();
		}catch(IOException e) {
			e.printStackTrace();
			throw new RuntimeException("Failed to load errorPane in Presenter");
		}
		errorController = errorPaneLoader.<ErrorPanelController>getController();
		controllerFileIndexes = new int[controllers_.length];
		for(int i = 0;i < controllerFileIndexes.length;++i) {
			controllerFileIndexes[i]= -1; 
		}
		//Maximum send 3 files at the same time
		threadPool = Executors.newFixedThreadPool(3,new ThreadFactory(){
			public Thread newThread(Runnable r){
				Thread thread = Executors.defaultThreadFactory().newThread(r);
				thread.setDaemon(true);
				return thread;
			}
		});
	}
	//exitWithConnectionError method should be called in JavaFX Application Thread
	public void exitWithConnectionError() {
		Scene newScene = new Scene(errorPane);
		errorController.setMessage("Connection failed,\nthe program will exit");
		
		Stage stage = new Stage();
		stage.initModality(Modality.APPLICATION_MODAL);
		errorController.closeButton.setOnAction(aEvent->stage.close());
		stage.setScene(newScene);
		stage.showAndWait();
		//make the JavaFX Application Thread exit
		//threadPool.shutdownNow();
		Platform.exit();
	}
	//fileReceived method should be called in JavaFX Application Thread
	public void fileReceived(int fileID) {
		for(int i = 0;i < controllerFileIndexes.length;++i) {
			if(controllerFileIndexes[i] == fileID) {
				controllers[i].resLabel.setText("File sent");
			}
		}
	}
}
