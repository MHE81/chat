package First;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.TextField;
import javafx.scene.layout.AnchorPane;
import javafx.stage.Stage;

import java.io.IOException;

public class newGameController {
    @FXML
    private AnchorPane secPane;
    @FXML
    private Button backBttn;
    @FXML
    private Button continueButton;
    @FXML
    private TextField txtUsername;
    @FXML
    private TextField txtPassword;

    private Client client;

    newGameController(){}

    public void backButtonPushed(ActionEvent event) throws IOException {
        Parent mainParent = FXMLLoader.load(getClass().getResource("ClientFXUI.fxml"));
        Scene mainScene = new Scene(mainParent);

        //this line gets the stage information
        Stage window = (Stage) ((Node)event.getSource()).getScene().getWindow();
        window.setScene(mainScene);
        window.show();
    }
    public void continueButtonPushed(ActionEvent event) throws IOException {
        String username = txtUsername.getText();
        System.out.println(username);
        if(username.isEmpty() == false) {
            client.writer.println("Username");
            client.writer.println(username);
            Parent detailsParent = FXMLLoader.load(getClass().getResource("gameDetails.fxml"));
            Scene detailsScene = new Scene(detailsParent);

            //this line gets the stage information
            Stage window = (Stage) ((Node) event.getSource()).getScene().getWindow();
            window.setScene(detailsScene);
            window.show();
        }
    }
}
