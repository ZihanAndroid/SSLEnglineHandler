package fxml_controller;

import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.ProgressBar;

public class PanelController {
	@FXML public Button fileButton;
	@FXML public ProgressBar progressBar;
	@FXML public Label pathLabel;
	@FXML public Label resLabel;
	@FXML public Label timeLabel;
	@FXML public Label speedLabel;
	@FXML public Label leftLabel;
	@FXML public Button sendButton;
	
	@FXML private Label percentLabel;
	
	public PanelController() {}
	@FXML private void initialize() {
		progressBar.progressProperty().addListener((doubleProperty,oldValue,newValue)->{
			percentLabel.setText(String.format("%.0f%%",newValue.doubleValue()*100.0));
		});
		pathLabel.setText("");
		resLabel.setText("");
		timeLabel.setText("");
		speedLabel.setText("");
		leftLabel.setText("");
	}
}
