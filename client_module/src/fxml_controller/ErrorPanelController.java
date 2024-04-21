package fxml_controller;


import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.text.Text;
import javafx.scene.text.TextFlow;

public class ErrorPanelController {
	@FXML private TextFlow msgTextFlow;
	
	@FXML public Button closeButton;
	
	public ErrorPanelController() {}
	public void setMessage(String message) {
		msgTextFlow.getChildren().add(new Text(message));
	}
}
