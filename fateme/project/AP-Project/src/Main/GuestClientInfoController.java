package Main;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.TextField;
import javafx.stage.Stage;
import java.io.IOException;

public class GuestClientInfoController extends GameScene{

    @FXML
    private TextField jTxtUsername;

    @FXML
    void jBackButtonPushed(ActionEvent event) throws IOException {
        client.writer.writeUTF("Back");
        System.out.println("Back Button Pushed");
        Parent jMainParent = FXMLLoader.load(getClass().getResource("Client.fxml"));
        Scene jMainScene = new Scene(jMainParent);

        //this line gets the stage information
        Stage window = (Stage) ((Node)event.getSource()).getScene().getWindow();
        window.setScene(jMainScene);
        window.show();
    }
    @FXML
    void jContinueButtonPushed(ActionEvent event) throws IOException {
        String username = jTxtUsername.getText();
        if(!username.isEmpty()) {
            System.out.println(username);
            client.writer.writeUTF("Username");
            client.writer.writeUTF(username);

            Parent listParent = FXMLLoader.load((getClass().getResource("joinGame.fxml")));
            Scene detailsScene = new Scene(listParent);

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
