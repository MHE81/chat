package Main;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.DialogPane;
import javafx.scene.control.TextField;
import javafx.stage.Stage;
import java.io.IOException;

public class NewGameController extends GameScene{
    @FXML
    private TextField txtUsername;

    @FXML
    private Button continueButton;

    @FXML
    private Button backButton;

    @FXML
    private DialogPane usernameAlert;

    String username;

    @FXML
    void backButtonPushed(ActionEvent event) throws IOException {
        client.writer.writeUTF("Back");
        System.out.println("Back Button Pushed");
        Parent mainParent = FXMLLoader.load(getClass().getResource("Client.fxml"));
        Scene mainScene = new Scene(mainParent);

        //this line gets the stage information
        Stage window = (Stage) ((Node)event.getSource()).getScene().getWindow();
        window.setScene(mainScene);
        window.show();
    }

    @FXML
    void continueButtonPushed(ActionEvent event) throws IOException {
        username = txtUsername.getText();
        if(!username.isEmpty()) {
            System.out.println(username);
            client.writer.writeUTF("Username");
            client.writer.writeUTF(username);

            Parent detailsParent = FXMLLoader.load(getClass().getResource("GameInfo.fxml"));
            Scene detailsScene = new Scene(detailsParent);

            //this line gets the stage information
            Stage window = (Stage) ((Node) event.getSource()).getScene().getWindow();
            window.setScene(detailsScene);
            window.show();
        }
        else{
            Alert alert = new Alert(Alert.AlertType.WARNING);
            alert.setTitle("هشدار");
            alert.setHeaderText("فیلد مورد نیاز خالی است!");
            alert.setContentText("پر کردن فیلد \"نام\" الزامی است!");
            alert.showAndWait();
        }
    }
}

