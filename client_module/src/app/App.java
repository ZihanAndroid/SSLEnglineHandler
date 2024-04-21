package app;

import java.io.IOException;
import java.net.URL;

import fxml_controller.ErrorPanelController;
import fxml_controller.PanelController;
import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import javafx.stage.StageStyle;
import netClient.NetClient;
import presenter.Presenter;

public class App extends Application{

	public static void main(String[] args) {
		Application.launch(args);
	}

	@SuppressWarnings("unused")
	@Override public void start(Stage stage) {
		URL fxmlUrl = getClass().getResource("/resources/fxml/clientPanel.fxml");
		System.out.println(fxmlUrl == null);
		FXMLLoader fxmlLoader1 = new FXMLLoader(fxmlUrl);
		FXMLLoader fxmlLoader2 = new FXMLLoader(fxmlUrl);
		FXMLLoader fxmlLoader3 = new FXMLLoader(fxmlUrl);
		FXMLLoader errorPaneLoader = new FXMLLoader(getClass().getResource("/resources/fxml/errorPanel.fxml"));
		
	
		GridPane gridPane1 = null,gridPane2 = null, gridPane3 = null;
		VBox errorPane = null;
		try {
			gridPane1 = fxmlLoader1.<GridPane>load();
			gridPane2 = fxmlLoader2.<GridPane>load();
			gridPane3 = fxmlLoader3.<GridPane>load();
			errorPane = errorPaneLoader.<VBox>load();
		}catch(IOException e) {
			System.out.println("Failed to load fxml files");
			e.printStackTrace();
			return;
		}
		
		PanelController fxmlController1 = fxmlLoader1.<PanelController>getController();
		PanelController fxmlController2 = fxmlLoader2.<PanelController>getController();
		PanelController fxmlController3 = fxmlLoader3.<PanelController>getController();
		ErrorPanelController errorController = errorPaneLoader.<ErrorPanelController>getController();
		//server in "localhost",4646
		NetClient netClient = null;
		try {
			netClient = new NetClient("localhost",4647);
		}catch(Exception e) {
			errorController.setMessage("Failed to connect to the server\nTry again Later.");
			errorController.closeButton.setOnAction(event->stage.close());
			Scene scene = new Scene(errorPane);
			stage.setScene(scene);
			stage.setTitle("Error");
			stage.show();
			return;
		}
		//netClient is the same for all 3 Presenters
		Presenter presenter = new Presenter(stage, new PanelController[] {fxmlController1,fxmlController2,fxmlController3}, netClient);
		
		HBox rootPane = new HBox(gridPane1,gridPane2,gridPane3);
		
		Button closeBtn = new Button("Close");
		final NetClient client = netClient; 
		closeBtn.setOnAction(event->{
			stage.close();
			client.exit();
		});
		VBox rootBox = new VBox(closeBtn,rootPane);
		
		
		rootPane.setPrefHeight(Region.USE_COMPUTED_SIZE);
		rootPane.setPrefWidth(Region.USE_COMPUTED_SIZE);
		Scene scene = new Scene(rootBox);
		stage.setScene(scene);
		stage.initStyle(StageStyle.UNDECORATED);
		stage.setTitle("File transfer client");
		stage.show();
	}
}